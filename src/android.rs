//! Android half of the kit (feature `android`): calls into the Java class
//! `dev.forgesworn.release.Updater` (HttpURLConnection download thread,
//! PackageInstaller session, `UpdateReceiver`; see `android/README.md`). The Rust
//! side decides WHAT to install; this only moves the bytes.
//!
//! `Updater` has no native methods: Rust calls its static methods and polls
//! `status()` / `done()` / `total()` / `message()`, so there is nothing to
//! register. The class is loaded through the app's class loader (a native
//! thread's `FindClass` only sees the system loader) and cached.
//!
//! [`AndroidInstaller`] is an [`ApkInstaller`] over these calls. The JavaVM and
//! the Activity come from `ndk_context`, which `android-activity` (or any glue
//! that sets it up) fills in.

use crate::installer::{ApkInstaller, ApkJob, ApkStatus, ANOTHER_INSTALL};
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use std::sync::Mutex;

const CLASS: &str = "dev.forgesworn.release.Updater";

// Updater.java status codes.
const IDLE: i32 = 0;
const DOWNLOADING: i32 = 1;
const INSTALLING: i32 = 2;
const CONFIRM_READY: i32 = 3;
const WAITING_USER: i32 = 4;
const NEEDS_PERMISSION: i32 = 5;
const FAILED: i32 = 6;
const INSTALLED: i32 = 7;

static UPDATER: Mutex<Option<GlobalRef>> = Mutex::new(None);

fn vm() -> Option<JavaVM> {
    let ctx = std::panic::catch_unwind(ndk_context::android_context).ok()?;
    if ctx.vm().is_null() {
        return None;
    }
    // SAFETY: the pointer is the process JavaVM, set up by the Android glue.
    unsafe { JavaVM::from_raw(ctx.vm().cast()) }.ok()
}

/// Run `f` with an attached `JNIEnv` inside a local-reference frame. Java
/// exceptions are logged and cleared, panics caught; any failure is `None`.
fn with_env<T>(what: &str, f: impl FnOnce(&mut JNIEnv) -> jni::errors::Result<T>) -> Option<T> {
    let run = std::panic::AssertUnwindSafe(|| -> Option<T> {
        let vm = vm()?;
        let mut env = match vm.attach_current_thread() {
            Ok(e) => e,
            Err(e) => {
                log::warn!("release-kit: {what}: no JNI env ({e})");
                return None;
            }
        };
        match env.with_local_frame(32, |env| f(env)) {
            Ok(v) => Some(v),
            Err(e) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_describe();
                    let _ = env.exception_clear();
                }
                log::warn!("release-kit: {what} failed: {e}");
                None
            }
        }
    });
    std::panic::catch_unwind(run).unwrap_or_else(|_| {
        log::error!("release-kit: {what} panicked");
        None
    })
}

/// `Updater`'s class (loaded once through the Activity's class loader).
fn class() -> Option<GlobalRef> {
    let mut slot = UPDATER.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = &*slot {
        return Some(c.clone());
    }
    let found = with_env("updater: load Updater", |env| {
        let ctx = std::panic::catch_unwind(ndk_context::android_context).map_err(|_| jni::errors::Error::NullPtr("android context"))?;
        if ctx.context().is_null() {
            return Err(jni::errors::Error::NullPtr("android context"));
        }
        // SAFETY: the context the glue registered with ndk_context
        // (with NativeActivity, the Activity's global reference). Only its
        // class loader is used. Not owned: never deleted.
        let ctx_obj = unsafe { JObject::from_raw(ctx.context().cast()) };
        let loader = env.call_method(&ctx_obj, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?.l()?;
        let name = env.new_string(CLASS)?;
        let cls = env.call_method(&loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[JValue::Object(&name)])?.l()?;
        env.new_global_ref(cls)
    });
    if found.is_none() {
        log::warn!("release-kit: Updater class unavailable");
    }
    *slot = found.clone();
    found
}

/// `Updater.<name><sig>(args)` and the closure's reading of the result.
fn call<T>(name: &str, sig: &str, args: &[JValue], read: impl FnOnce(&mut JNIEnv, jni::objects::JValueOwned) -> jni::errors::Result<T>) -> Option<T> {
    let cls = class()?;
    with_env(name, |env| {
        let c: &JClass = cls.as_obj().into();
        let v = env.call_static_method(c, name, sig, args)?;
        read(env, v)
    })
}

fn string_of(env: &mut JNIEnv, v: jni::objects::JValueOwned) -> jni::errors::Result<String> {
    let o = v.l()?;
    if o.is_null() {
        return Ok(String::new());
    }
    Ok(env.get_string(&JString::from(o))?.into())
}

/// `Updater.ownPackage()`: `Context.getPackageName()` of the running app.
pub fn own_package() -> Option<String> {
    call("ownPackage", "()Ljava/lang/String;", &[], |env, v| string_of(env, v)).filter(|s| !s.is_empty())
}

/// SHA-256 (lowercase hex) of this app's signing certificate.
pub fn cert_sha256() -> Option<String> {
    call("certSha256", "()Ljava/lang/String;", &[], |env, v| string_of(env, v)).filter(|s| s.len() == 64)
}

/// Start a job: `Updater.start(urls, sha256, size)` for an update of this app (no
/// package named), `Updater.startSibling(urls, sha256, size, package, cert, releaseCert)`
/// for another package. Either way the downloaded file's package and signing
/// certificate are checked in Java before the installer runs; for a sibling, against
/// the catalog's pinned certificate AND the release event's, independently.
/// `Err(ANOTHER_INSTALL)` when Java is busy with another package's attempt (it
/// changed nothing), so the caller says so instead of following the wrong attempt.
pub fn start(job: &ApkJob) -> Result<(), String> {
    let joined = job.urls.join("\n");
    let r = with_env("updater: start", |env| {
        let cls = class().ok_or(jni::errors::Error::NullPtr("Updater class"))?;
        let u = env.new_string(&joined)?;
        let h = env.new_string(&job.sha256)?;
        let c: &JClass = cls.as_obj().into();
        if job.package.is_empty() {
            env.call_static_method(c, "start", "(Ljava/lang/String;Ljava/lang/String;J)Z", &[JValue::Object(&u), JValue::Object(&h), JValue::Long(job.size as i64)])?.z()
        } else {
            let p = env.new_string(&job.package)?;
            let c1 = env.new_string(&job.cert)?;
            let c2 = env.new_string(&job.release_cert)?;
            env.call_static_method(
                c,
                "startSibling",
                "(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z",
                &[JValue::Object(&u), JValue::Object(&h), JValue::Long(job.size as i64), JValue::Object(&p), JValue::Object(&c1), JValue::Object(&c2)],
            )?
            .z()
        }
    });
    match r {
        Some(true) => Ok(()),
        Some(false) => Err(ANOTHER_INSTALL.to_string()),
        None => Err("Couldn't start the download.".to_string()),
    }
}

/// `Updater.installedVersionCode(package)`: -1 when it is not installed.
pub fn installed_version_code(package: &str) -> Option<u32> {
    let code = with_env("updater: installedVersionCode", |env| {
        let cls = class().ok_or(jni::errors::Error::NullPtr("Updater class"))?;
        let p = env.new_string(package)?;
        let c: &JClass = cls.as_obj().into();
        env.call_static_method(c, "installedVersionCode", "(Ljava/lang/String;)J", &[JValue::Object(&p)])?.j()
    })?;
    // -1: not installed. A versionCode past u32 is "newer than anything", never "not installed".
    (code >= 0).then(|| u32::try_from(code).unwrap_or(u32::MAX))
}

/// `Updater.launch(package)`: open the installed app.
pub fn launch(package: &str) -> Result<(), String> {
    let opened = with_env("updater: launch", |env| {
        let cls = class().ok_or(jni::errors::Error::NullPtr("Updater class"))?;
        let p = env.new_string(package)?;
        let c: &JClass = cls.as_obj().into();
        env.call_static_method(c, "launch", "(Ljava/lang/String;)Z", &[JValue::Object(&p)])?.z()
    });
    if opened == Some(true) {
        Ok(())
    } else {
        Err("Couldn't open it. Try from your app list.".to_string())
    }
}

/// Where the download / install stands.
pub fn status() -> ApkStatus {
    let Some(code) = call("status", "()I", &[], |_, v| v.i()) else {
        return ApkStatus::Failed("Updates aren't available on this phone.".into());
    };
    match code {
        IDLE => ApkStatus::Idle,
        DOWNLOADING => {
            let done = call("done", "()J", &[], |_, v| v.j()).unwrap_or(0).max(0) as u64;
            let total = call("total", "()J", &[], |_, v| v.j()).unwrap_or(0).max(0) as u64;
            ApkStatus::Downloading { done, total }
        }
        INSTALLING => ApkStatus::Installing,
        CONFIRM_READY | WAITING_USER => ApkStatus::WaitingForUser,
        NEEDS_PERMISSION => ApkStatus::NeedsPermission,
        INSTALLED => ApkStatus::Installed,
        FAILED => {
            let m = call("message", "()Ljava/lang/String;", &[], |env, v| string_of(env, v)).unwrap_or_default();
            ApkStatus::Failed(if m.is_empty() { "The update failed.".into() } else { m })
        }
        _ => ApkStatus::Failed("The update failed.".into()),
    }
}

/// `Updater.activePkg()`: the package the current (or most recent) install attempt is for.
pub fn active_package() -> Option<String> {
    call("activePkg", "()Ljava/lang/String;", &[], |env, v| string_of(env, v)).filter(|s| !s.is_empty())
}

/// `Updater.cancel()`: stop the running download, or drop an attempt parked at Android's prompt.
pub fn cancel() {
    let _ = call("cancel", "()V", &[], |_, _| Ok(()));
}

/// `ACTION_MANAGE_UNKNOWN_APP_SOURCES` for this app.
pub fn open_install_settings() {
    let _ = call("openInstallSettings", "()V", &[], |_, _| Ok(()));
}

/// An [`ApkInstaller`] over `dev.forgesworn.release.Updater`.
#[derive(Clone, Copy, Debug, Default)]
pub struct AndroidInstaller;

impl ApkInstaller for AndroidInstaller {
    fn can_install_apk(&self) -> bool {
        true
    }

    fn running_package(&mut self) -> Option<String> {
        own_package()
    }

    fn own_cert_sha256(&mut self) -> Option<String> {
        cert_sha256()
    }

    fn apk_start(&mut self, job: &ApkJob) -> Result<(), String> {
        start(job)
    }

    fn apk_status(&mut self) -> ApkStatus {
        status()
    }

    fn apk_cancel(&mut self) {
        cancel();
    }

    fn apk_active_package(&mut self) -> Option<String> {
        active_package()
    }

    fn apk_open_install_settings(&mut self) {
        open_install_settings();
    }

    fn installed_version_code(&mut self, package: &str) -> Option<u32> {
        installed_version_code(package)
    }

    fn open_package(&mut self, package: &str) -> bool {
        launch(package).is_ok()
    }
}
