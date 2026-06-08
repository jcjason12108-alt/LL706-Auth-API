=== LL706 Auth API ===
Contributors: jcjason12108-alt
Tags: authentication, jwt, rest api, member approval
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 0.9.4
License: GPL-2.0-or-later

WordPress login, manual approval, JWT auth, and work-log REST endpoints for LL706 mobile and web apps.

== Description ==

LL706 Auth API powers LL706 mobile and web app authentication with hardened login, membership approval, JSON Web Token authentication, login history, a remote Ask Bruno dashboard form card, and member work-log endpoints.

== Installation ==

1. Upload the `ll706-auth-api` folder to `wp-content/plugins/`.
2. Activate LL706 Auth API from Plugins in the WordPress dashboard.
3. Open Settings > LL706 Auth API to configure the JWT secret, approval meta key, dashboard form card, token lifetimes, and login log retention.

== Frequently Asked Questions ==

= How are plugin updates delivered? =

Updates are checked from the `main` branch of `https://github.com/jcjason12108-alt/LL706-Auth-API/` using Plugin Update Checker.

= Does the updater need a GitHub token? =

No. This repository is public, so the updater intentionally avoids GitHub authentication. If GitHub returns 403 on a live site, manually upload the latest ZIP once so the installed updater no longer sends stale server tokens.

== Changelog ==

= 0.9.4 =
* Removed GitHub updater authentication for this public repository to avoid stale server tokens causing GitHub API 403 errors.

= 0.9.3 =
* Moved Dashboard Form Card settings into their own first admin tab.
* Split dashboard form settings into their own settings group so saving that tab cannot reset auth settings.

= 0.9.2 =
* Switched updater authentication to the plugin-specific `LL706_AUTH_API_GITHUB_TOKEN`.
* Stopped using the generic `PLUGIN_UPDATE_GITHUB_TOKEN` value so unrelated tokens cannot trigger GitHub API 403 errors.

= 0.9.1 =
* Added remote-controlled Ask Bruno dashboard form-card settings.
* Added public GET /wp-json/ll706/v1/dashboard-form configuration endpoint.
* Sanitized and validated dashboard form title, subtitle, button title, URL, audience, and update timestamp.

= 0.9.0 =
* Confirmed compatibility with WordPress 7.0 and PHP 7.4.
* Hardened authenticated REST route permission callbacks.
* Hardened admin profile access updates with nonce, capability, and state validation.
* Normalized settings input with wp_unslash before sanitization.

= 0.8.3 =
* Added Plugin Update Checker 5.6 for GitHub-based automatic updates.
* Configured branch-only update detection from the `main` branch.
* Added optional GitHub token support.

= 0.8.2 =
* Added login history retention, CSV export, and per-user work-log API support.
