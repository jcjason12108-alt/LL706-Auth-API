# LL706 Auth API

WordPress plugin that powers the LL706 mobile and web apps with hardened login, membership approval, and JSON Web Token (JWT) authentication. It also exposes an admin workflow for approving or blocking a member’s access without touching their WordPress account.

## Requirements

- WordPress 6.0 or higher
- Tested up to WordPress 7.0
- PHP 7.4 or higher
- Android Restore Credentials endpoints require PHP 8.0 or higher and OpenSSL. Other plugin features retain PHP 7.4 compatibility.

## Features

- Login endpoint that accepts username or email and issues signed JWT tokens with configurable TTLs per role.
- Member self‑registration endpoint that collects profile meta (Ultimate Member compatible) and queues the account for manual approval.
- `/me` endpoint that validates tokens, rehydrates Ultimate Member fields, and returns the current user payload.
- Public `/dashboard-form` endpoint for a remote-controlled Ask Bruno dashboard form card.
- Public `/login-info` endpoint for a remote-controlled, sanitized rich-text card on the AskBruno login screen.
- Per-user work-log storage with authenticated create, read, update, and soft-delete endpoints.
- Per-user work-log reminder preferences with authenticated read/update endpoints for app-local scheduling.
- Shared Barstow LMIT weather by work date, cached in WordPress and refreshed from Open-Meteo without member GPS or work-log data leaving the server.
- Public Android Digital Asset Links document at `/.well-known/assetlinks.json` so supported password managers can share saved website credentials with the Play-signed AskBruno app.
- Android Restore Credentials endpoints that verify a transferred restore key and issue a new short-lived app token.
- Admin settings page with separate Dashboard Form Card, Login History, Overview, and Settings tabs.
- Admin settings page with separate Dashboard Form Card, Login Information Card, Login History, Overview, and Settings tabs.
- Per-user app login summary showing each member’s latest successful app login, token status, IP, and user agent.
- CSV export for the last-login summary.
- Automatic login log retention cleanup with a configurable number of days.
- Per‑user access controls rendered on the user edit screen and the Users table (Approve / Block / Auto) so admins can toggle app access in one click.
- Automatic integration with Ultimate Member approvals via the `um_after_user_is_approved` hook.
- Automatic plugin updates from the `main` branch of `https://github.com/jcjason12108-alt/LL706-Auth-API/` using Plugin Update Checker.

## Installation

1. Copy the entire plugin directory into `wp-content/plugins/ll706-auth-api/` (or clone this repository there).
2. In the WordPress dashboard, activate **LL706 Auth API** under *Plugins → Installed Plugins*.
3. Open *Settings → LL706 Auth API* to configure the JWT secret, approval meta key, dashboard form card, login information card, token lifetimes, and login log retention. Changing the secret or the “Force Logout” button invalidates existing tokens.
4. Use the *Overview* tab for built-in documentation and the *Login History* tab for recent app login activity and CSV export.

## REST API

All routes live under the namespace `ll706/v1`.

| Endpoint | Method | Description | Expected Params |
| --- | --- | --- | --- |
| `/login` | `POST` | Authenticate an existing member, vet approval status, and return a JWT payload. | `username` (or email), `password` |
| `/register` | `POST` | Create a pending member and store Ultimate Member profile meta. | `username`, `password`, `email`, `first_name`, `last_name`, `local_number`, `email_opt_in` plus optional address/phone/card fields |
| `/dashboard-form` | `GET` | Return the public dashboard form-card configuration for the app. | None |
| `/login-info` | `GET` | Return sanitized rich text for the public AskBruno Login Information Card. | None |
| `/me` | `GET` | Validate a token and return the hydrated user payload. | `Authorization: Bearer <token>` header |
| `/restore-credential/register-options` | `POST` | Create a short-lived WebAuthn registration challenge. | `Authorization: Bearer <token>` header |
| `/restore-credential/register` | `POST` | Verify and save the Android restore public key. | Bearer token, `flow_id`, `credential_json` |
| `/restore-credential/auth-options` | `POST` | Create a short-lived authentication challenge. | None |
| `/restore-credential/auth` | `POST` | Verify the transferred key and issue a fresh app token. | `flow_id`, `credential_json` |
| `/restore-credential/revoke` | `POST` | Revoke restore keys when a member logs out. | `Authorization: Bearer <token>` header |
| `/work-log` | `GET` | Return the authenticated member’s non-deleted work-log entries. | `Authorization: Bearer <token>` header |
| `/work-log` | `POST` | Create a work-log entry for the authenticated member. | `Authorization: Bearer <token>` header plus `work_date`, `shift` (`1st`, `2nd`, or `3rd`; numeric `1`, `2`, and `3` are normalized), `work_items`, and optional `entry_uuid`, `doubled`, `supervisor`, `worked_with`, `notes` |
| `/work-log/{entry_uuid}` | `PUT` | Update one work-log entry owned by the authenticated member. | `Authorization: Bearer <token>` header plus the same body fields as create |
| `/work-log/{entry_uuid}` | `DELETE` | Soft-delete one work-log entry owned by the authenticated member. | `Authorization: Bearer <token>` header |
| `/work-log-reminder` | `GET` | Return the authenticated member’s work-log reminder settings. | `Authorization: Bearer <token>` header |
| `/work-log-reminder` | `PUT` | Save the authenticated member’s work-log reminder settings. | `Authorization: Bearer <token>` header plus optional `enabled`, `days`, `time`, and `timezone` |
| `/work-log-weather` | `GET` | Return Barstow LMIT weather for a work date, or `weather: null` when unavailable. | `Authorization: Bearer <token>` header plus `date=YYYY-MM-DD` query parameter |

Work-log reminder settings are stored as one per-user WordPress user-meta record. The app is responsible for scheduling local notifications; the API does not create or send reminder notifications.

Weather uses the fixed worksite at 200 North Avenue H, Barstow, CA 92311. The response includes the daily high and low in °F, mean relative humidity in percent, maximum wind speed in mph, and `status` (`forecast` for today or `historical` for past dates). The weather is shared by date, not attached to a member's work-log row. A member with work-log backup disabled can request weather for a local-only entry without uploading that entry. Open-Meteo receives only the worksite coordinates and requested date. The response supplies `source_url` and `license_url`; the app must show Open-Meteo attribution near weather information and explain it in Work Log Info.

The plugin creates a separate weather cache table on activation or upgrade. WP-Cron schedules a daily refresh for 9:00 a.m. Pacific, covering the last seven days and today's forecast, and backfills earlier dates in 30-day chunks beginning with March 27, 2026 or the earliest server work-log date. WP-Cron runs when WordPress receives traffic, so an event may run later than its scheduled time. A requested date that is not cached can also be fetched on demand. Weather fetch or cache failures return `weather: null` or the last cached value; they do not change existing work-log entries.

## Android credential sharing

The plugin serves `https://www.iamll706.org/.well-known/assetlinks.json` with the `delegate_permission/common.get_login_creds` relation for `org.iamll706.askbruno`. Its SHA-256 fingerprint is the **Google Play app-signing certificate**, not the local upload key. The Android app includes an `asset_statements` reference to this URL. This associates saved website passwords with the app; it does not create accounts, change passwords, or bypass normal WordPress login and approval checks.

Deploy the plugin before publishing the Android version containing the manifest reference. Verify that the URL responds directly with HTTP 200, `Content-Type: application/json`, and no redirect. If the web server handles `/.well-known/` before WordPress, configure it to pass this path to WordPress or serve the same JSON as a static file. Then test autofill with a password saved for `www.iamll706.org` on a Play-installed build. The local `sha256.txt` is the upload certificate and must not replace the Play app-signing fingerprint in the asset links response.

Example reminder response:

```json
{
  "ok": true,
  "reminder": {
    "enabled": true,
    "days": ["mon", "tue", "wed", "thu", "fri"],
    "time": "17:00",
    "timezone": "America/Los_Angeles"
  }
}
```

Responses follow a consistent shape:

```json
// success
{ "ok": true, "token": "...", "expires_at": 1234567890, "user": { /* … */ } }

// error
{ "ok": false, "error": "not_approved", "message": "Your account is pending approval." }
```

Work-log responses use the same envelope:

```json
{
  "ok": true,
  "entry": {
    "entry_uuid": "4a1c3d58-7f4e-4d24-9db2-1f5dce32d7af",
    "work_date": "2026-03-30",
    "shift": "1st",
    "doubled": false,
    "supervisor": "Jane Smith",
    "worked_with": ["Alex", "Morgan"],
    "notes": "Routine maintenance",
    "work_items": [
      {
        "locomotive": "UP1234",
        "task_performed": "Oil change",
        "follow_up_color": "orange"
      },
      {
        "locomotive": "BNSF9988",
        "task_performed": "Inspection",
        "follow_up_color": null
      }
    ],
    "created_at": "2026-03-30 20:15:00",
    "updated_at": "2026-03-30 20:15:00",
    "deleted_at": null
  }
}
```

## Admin Access Controls

- **Users → All Users** now shows an **LL706 App** column with inline links:
  - **Approve**: set approval meta to `1`.
  - **Block**: set approval meta to `0` (login denied).
  - **Auto**: remove the meta key (legacy state treated as approved until explicitly blocked).
- **User Profile screen** displays the same radio controls. Saving updates the meta accordingly.

These controls write the meta key configured in the settings page so you can rename it to fit your data model.

## Ultimate Member Integration

- Registration stores the canonical `awaiting_admin_review` status across Ultimate Member’s expected meta keys.
- When Ultimate Member approves a member (`um_after_user_is_approved`), the plugin automatically marks the LL706 approval meta as `1`, allowing app logins immediately.

## Development

- Lint PHP before committing: `php -l 'LL706 Auth API.php'`.
- Restore Credentials uses the bundled MIT-licensed `lbuchs/webauthn` 2.2.0 library. Only the public key is stored by this plugin; Android handles private-key backup and device transfer. Password changes, app logout, account blocking, and global token invalidation stop restore sign-ins. The built-in Android origin list contains the Play app-signing certificate and the QA tablet's debug certificate. For other debug builds, define `LL706_RESTORE_EXTRA_CERT_SHA256` in `wp-config.php` as an array of additional signing-certificate SHA-256 fingerprints.
- To verify the complete flow, install the updated server before the app, sign in on an Android 9+ source device, and use Android Studio's **Backup App Data** and **Restore App Data** on a second device or emulator. Confirm the restored app reaches the signed-in screen without credentials, `/me` works with the new token, and explicit logout prevents another automatic sign-in. A local build needs its signing-certificate fingerprint in `LL706_RESTORE_EXTRA_CERT_SHA256`; the Play-signed build uses the built-in fingerprint.
- GitHub update checks require the repository root to contain `LL706 Auth API.php` directly, not inside an extra nested plugin folder.
- If GitHub returns 403 during update checks, define `LL706_AUTH_API_GITHUB_TOKEN` as a fine-grained GitHub token with read access to this repository. The generic `PLUGIN_UPDATE_GITHUB_TOKEN` constant or environment variable is also supported as a fallback.
- To force all tokens invalid, bump the `token_version` option from the settings page.
- Need to bulk approve legacy members? With WP‑CLI you can run:  
  `wp user list --field=ID | xargs -I % wp user meta update % ll706_approved 1`
  (replace `ll706_approved` if you changed the meta key).

## Changelog

### 0.9.20

- Added authenticated Barstow LMIT weather lookup, a separate daily weather cache, historical backfill, and a daily WP-Cron refresh.
- Kept work-log records and backup preferences independent of weather; app-local entries can look up weather by date.

### 0.9.19

- Accepted the QA tablet's debug signing certificate as an Android restore credential origin, alongside the Play app-signing certificate.

### 0.9.18

- Added Android zero-tap sign-in restoration backed by signed WebAuthn challenges and the existing approved-account token flow.

### 0.9.14

- Added authenticated `/work-log-reminder` GET and PUT endpoints for per-user reminder preferences.
- Store reminder preferences in one user-meta record without adding rows to the work-log table.

### 0.9.13

- Added a **Check for Update** button near the top of the plugin settings page.
- Added optional start and end scheduling for the Login Information Card.
- Added Transparent, Glass, and Solid Color card appearances with improved text contrast.
- Added a subtle text shadow for Transparent and Glass cards.
- Limited the news ticker to short single-paragraph messages; formatted multi-line messages now stay still automatically.

### 0.9.12

- Added an optional transparent background for the Login Information Card.
- Added a dark login-surface preview so transparent cards and their default white text can be reviewed before publishing.

### 0.9.11

- Added ready-to-use Quick Message presets to the Login Information Card settings.
- Presets fill the existing rich-text editor and remain editable before publishing.

### 0.9.10

- Replaced the manually scrollable Login Information Card option with an automatic right-to-left news ticker.
- Added Slow, Normal, and Fast ticker speed choices to the administrator settings and public `/login-info` response.

### 0.9.9

- Changed the Login Information Card background default to white and added an administrator-selectable background color.
- Added an optional scrollable card mode with a configurable 100–500 point/pixel maximum height.
- Added background and scrolling fields to the public `/login-info` response.

### 0.9.8

- Added a separate Login Information Card settings tab with a rich-text editor and saved-card preview.
- Added the public `GET /wp-json/ll706/v1/login-info` endpoint for supported AskBruno apps.
- Restricted login-card content to sanitized formatting and safe links, with scripts and embedded content removed.

### 0.9.7

- Recheck user approval on every authenticated REST request so blocking a user takes effect immediately.
- Updated the bundled Plugin Update Checker library from 5.6 to 5.7.

### 0.9.6

- Restored optional GitHub updater token support, preferring `LL706_AUTH_API_GITHUB_TOKEN` and falling back to `PLUGIN_UPDATE_GITHUB_TOKEN`.
- Updated WordPress compatibility metadata to 7.0.
- Tightened login/work-log table count queries to known plugin tables only.

### 0.9.5

- Version bump to verify the public GitHub updater path after removing updater authentication.

### 0.9.4

- Removed GitHub updater authentication for this public repository to avoid stale server tokens causing GitHub API 403 errors.

### 0.9.3

- Moved Dashboard Form Card settings into their own first admin tab.
- Split dashboard form settings into their own settings group so saving that tab cannot reset auth settings.

### 0.9.2

- Switched updater authentication to the plugin-specific `LL706_AUTH_API_GITHUB_TOKEN`.
- Stopped using the generic `PLUGIN_UPDATE_GITHUB_TOKEN` value so unrelated tokens cannot trigger GitHub API 403 errors.

### 0.9.1

- Added remote-controlled Ask Bruno dashboard form-card settings.
- Added public `GET /wp-json/ll706/v1/dashboard-form` configuration endpoint.
- Sanitized and validated dashboard form title, subtitle, button title, URL, audience, and update timestamp.

### 0.9.0

- Confirmed compatibility with WordPress 7.0 and PHP 7.4.
- Hardened authenticated REST route permission callbacks.
- Hardened admin profile access updates with nonce, capability, and state validation.
- Normalized settings input with wp_unslash before sanitization.

### 0.8.3

- Added Plugin Update Checker 5.6 for GitHub-based automatic updates.
- Configured branch-only update detection from the `main` branch.
- Added optional GitHub token support.

## License

GPL-2.0-or-later.
