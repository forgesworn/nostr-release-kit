package dev.forgesworn.release;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Which redirect targets an update download may follow. A mirror may send the
 * user's phone to a CDN, but never to a place a phone can reach and a CDN
 * cannot be: plain http, an address with a login in it, another port, a bare
 * IP address, {@code localhost} or a private name. The bytes are hash-checked
 * either way. This is a syntactic rule: it cannot see what a DNS name resolves to
 * (a name that points at a private address passes), so it narrows the requests a
 * mirror can make a phone send; it does not guarantee they stay on the public web.
 *
 * <p>Pure java.net, no Android classes, so a host-JDK test runs
 * {@code RedirectRuleTest} against it on the host JDK.
 */
final class RedirectRule {
    private RedirectRule() {}

    /**
     * Is {@code url} (already resolved against the page that redirected) fine
     * to follow? https, no userinfo, port absent or 443, and a host that is a
     * DNS name: dotted, letters/digits/hyphens, a top-level label that starts
     * with a letter (so no IPv4 in any spelling), and not {@code localhost}.
     */
    static boolean allows(String url) {
        if (url == null) {
            return false;
        }
        URI u;
        try {
            u = new URI(url);
        } catch (URISyntaxException e) {
            return false;
        }
        if (!"https".equalsIgnoreCase(u.getScheme()) || u.getRawUserInfo() != null) {
            return false;
        }
        String authority = u.getRawAuthority();
        if (authority == null || authority.indexOf('@') >= 0 || authority.endsWith(":")) {
            return false;
        }
        int port = u.getPort();
        if (port != -1 && port != 443) {
            return false;
        }
        return isDnsName(u.getHost());
    }

    /** A public DNS name: see {@link #allows}. */
    static boolean isDnsName(String host) {
        if (host == null || host.isEmpty() || host.length() > 253) {
            return false;
        }
        String h = host.toLowerCase(Locale.ROOT);
        if (h.equals("localhost") || h.endsWith(".localhost") || h.indexOf('.') < 0) {
            return false;
        }
        String[] labels = h.split("\\.", -1);
        for (String l : labels) {
            if (l.isEmpty() || l.length() > 63 || l.startsWith("-") || l.endsWith("-")) {
                return false;
            }
            for (int i = 0; i < l.length(); i++) {
                char ch = l.charAt(i);
                if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) {
                    return false;
                }
            }
        }
        char first = labels[labels.length - 1].charAt(0);
        return first >= 'a' && first <= 'z';
    }
}
