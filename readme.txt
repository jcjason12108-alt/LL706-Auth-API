=== LL706 Auth API ===
Contributors: jcjason12108-alt
Tags: authentication, jwt, rest api, member approval
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 7.4
Stable tag: 0.8.3
License: GPL-2.0-or-later

WordPress login, manual approval, JWT auth, and work-log REST endpoints for LL706 mobile and web apps.

== Description ==

LL706 Auth API powers LL706 mobile and web app authentication with hardened login, membership approval, JSON Web Token authentication, login history, and member work-log endpoints.

== Installation ==

1. Upload the `ll706-auth-api` folder to `wp-content/plugins/`.
2. Activate LL706 Auth API from Plugins in the WordPress dashboard.
3. Open Settings > LL706 Auth API to configure the JWT secret, approval meta key, token lifetimes, and login log retention.

== Frequently Asked Questions ==

= How are plugin updates delivered? =

Updates are checked from the `main` branch of `https://github.com/jcjason12108-alt/LL706-Auth-API/` using Plugin Update Checker.

= Does a private GitHub repository token work? =

Yes. Define `PLUGIN_UPDATE_GITHUB_TOKEN` as a PHP constant or environment variable and the updater will authenticate GitHub requests with it.

== Changelog ==

= 0.8.3 =
* Added Plugin Update Checker 5.6 for GitHub-based automatic updates.
* Configured branch-only update detection from the `main` branch.
* Added optional GitHub token support through `PLUGIN_UPDATE_GITHUB_TOKEN`.

= 0.8.2 =
* Added login history retention, CSV export, and per-user work-log API support.
