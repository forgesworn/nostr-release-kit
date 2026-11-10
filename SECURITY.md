# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub security advisories:
open the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/forgesworn/nostr-release-kit/security/advisories/new).

Do not open a public issue for a vulnerability. Include what you found, how to
reproduce it, and which version or commit you tested. You will get an
acknowledgement, and a fix or an explanation, as soon as the maintainers can
manage; please allow a reasonable time before disclosing publicly.

## Scope

In scope: the release-event verification rules (`parse_release`, the canonical
Blossom URL rule, the package and certificate checks in `ApkCheck`), the
download and install path in `Updater.java`, and the publisher in `tools/`.

Out of scope: an app that pins the wrong key or certificate, a compromised
release key (rotating it needs a new APK installed by hand), and Android or
Blossom server bugs.
