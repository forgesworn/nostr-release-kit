package dev.forgesworn.release;

/**
 * Host-JDK test of RedirectRule (run by the app's build before d8; not in
 * the APK). Exit status 0 = pass.
 */
public final class RedirectRuleTest {
    private static int failures = 0;

    private static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
            System.err.println("FAIL: " + what);
        }
    }

    private static void allowed(String url) {
        check(RedirectRule.allows(url), "allowed: " + url);
    }

    private static void refused(String url) {
        check(!RedirectRule.allows(url), "refused: " + url);
    }

    public static void main(String[] args) {
        allowed("https://nostr.download/abc.apk");
        allowed("https://cdn.example.com/a/b?x=1");
        allowed("https://cdn.example.com:443/a");
        allowed("HTTPS://Cdn.Example.COM/a");
        allowed("https://xn--bcher-kva.example/a");
        allowed("https://a-b.c-d.example/a");

        // Scheme.
        refused("http://nostr.download/abc.apk");
        refused("ftp://nostr.download/abc.apk");
        refused("file:///data/x");
        refused("//nostr.download/abc.apk");
        refused("/abc.apk");
        refused("");
        refused(null);

        // No userinfo.
        refused("https://user@nostr.download/a");
        refused("https://user:pw@nostr.download/a");
        refused("https://nostr.download@evil.example/a");
        refused("https://:@nostr.download/a");

        // Port: absent or 443.
        refused("https://nostr.download:8443/a");
        refused("https://nostr.download:80/a");
        refused("https://nostr.download:444/a");
        refused("https://nostr.download:/a");

        // The host must be a DNS name: no IP literal, no localhost, a dot.
        refused("https://127.0.0.1/a");
        refused("https://10.0.0.5/a");
        refused("https://192.168.1.1:443/a");
        refused("https://[::1]/a");
        refused("https://[2001:db8::1]/a");
        refused("https://[::ffff:127.0.0.1]/a");
        refused("https://localhost/a");
        refused("https://LOCALHOST/a");
        refused("https://localhost.:443/a");
        refused("https://app.localhost/a");
        refused("https://intranet/a");
        refused("https://2130706433/a");
        refused("https://0x7f.0x0.0x0.0x1/a");
        refused("https://127.1/a");
        refused("https://example.com./a");
        refused("https://.example.com/a");
        refused("https://exa_mple.com/a");
        refused("https://exa mple.com/a");
        refused("https:///a");
        refused("https://");

        if (failures > 0) {
            System.err.println(failures + " failure(s)");
            System.exit(1);
        }
        System.out.println("RedirectRuleTest: ok");
    }
}
