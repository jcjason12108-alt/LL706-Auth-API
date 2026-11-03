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
- Private Work Log photo backup endpoints with per-member access and a separate file-storage directory.
- Optional service-key-only lineup intake and WordPress storage for extracted rows from backed-up photos.
- Optional read-only Work Log and photo-reference query route for n8n, keyed by a requested WordPress user ID and protected by a separate service key.
- Per-user work-log reminder preferences with authenticated read/update endpoints for app-local scheduling.
- Shared Barstow LMIT weather by work date, cached in WordPress and refreshed from Open-Meteo without member GPS or work-log data leaving the server.
- Public Android Digital Asset Links document at `/.well-known/assetlinks.json` so supported password managers can share saved website credentials with the Play-signed AskBruno app.
- Android Restore Credentials endpoints that verify a transferred restore key and issue a new short-lived app token.
- Top-level **LL706 Auth API** admin menu with Dashboard Form Card, Login Information Card, Login History, Work Log Photos, Overview, and Settings tabs.
- Per-user app login summary showing each member’s latest successful app login, token status, IP, and user agent.
- CSV export for the last-login summary.
- Automatic login log retention cleanup with a configurable number of days.
- Per‑user access controls rendered on the user edit screen and the Users table (Approve / Block / Auto) so admins can toggle app access in one click.
- Automatic integration with Ultimate Member approvals via the `um_after_user_is_approved` hook.
- Automatic plugin updates from the `main` branch of `https://github.com/jcjason12108-alt/LL706-Auth-API/` using Plugin Update Checker.

## Installation

1. Copy the entire plugin directory into `wp-content/plugins/ll706-auth-api/` (or clone this repository there).
2. In the WordPress dashboard, activate **LL706 Auth API** under *Plugins → Installed Plugins*.
3. Open **LL706 Auth API** in the left admin menu to configure the JWT secret, approval meta key, dashboard form card, login information card, token lifetimes, and login log retention. Changing the secret or the “Force Logout” button invalidates existing tokens.
4. Use the *Overview* tab for built-in documentation and the *Login History* tab for recent app login activity and CSV export.

### Private Work Log photo storage

Photo uploads are disabled until the server administrator creates a persistent, writable directory **outside the web server's document root** and configures it in `wp-config.php` (or another protected PHP configuration file):

```php
define('LL706_WORK_LOG_PHOTO_DIR', '/absolute/private/path/askbruno-work-log-photos');
```

Do not point this at `wp-content/uploads`, the plugin directory, or any other web-accessible path. The plugin refuses a path inside WordPress or the current web document root, but the host must confirm that no other virtual host exposes the chosen directory. Include the photo directory in site backups and verify a restore. The **Work Log Photos** admin tab reports whether the directory is ready, stored photo count and bytes, and pending file deletions. It does not display photo contents. Only compatible AskBruno app builds upload photos; older builds remain entry-only.

Only JPEG uploads are accepted, up to 5 MiB and 3000 pixels on the longest side. Each entry can have up to 20 backed-up photos, and each member can use up to 1 GiB; both limits are overrideable with the `LL706_WORK_LOG_PHOTO_MAX_PER_ENTRY` and `LL706_WORK_LOG_PHOTO_MAX_USER_BYTES` constants. Uploads for one member are serialized so simultaneous requests cannot bypass those limits. The apps already save compressed 2000-pixel JPEGs. Files are named by UUID in the private directory; the database stores member/entry ownership, the original local filename, caption, size, hash, and timestamps. The plugin does not encrypt files at rest; whether the host encrypts its disks and backups must be verified separately. Work Log deletion and WordPress user deletion queue associated photo files for removal. The existing daily cleanup job retries pending deletions if the storage directory was unavailable.

In compatible AskBruno builds, the single **Back Up Work Log** setting controls both written entries and saved photos. The app saves both on the device first, then syncs them privately when backup is on; draft photos stay on the device until the entry is saved. Turning backup off stops future syncing but leaves previously-backed-up copies in the account. With backup on, deleting a photo or Work Log entry removes its remote copy; the app also offers a separate choice to delete device and backed-up entries and photos together. For an individual deleted photo, the plugin retains its UUID as a small deletion record while the Work Log entry exists, and compatible apps remove stale copies on other devices. This prevents an older device from re-uploading the deleted photo. The photo API serves only the authenticated member's files and creates no public photo links. The plugin's Overview tab explains this behavior for administrators.

### Lineup service preparation

The lineup service is disabled until a separate secret of at least 32 characters is added to protected server configuration. Store the matching value in an n8n credential, not in a workflow export or an app:

```php
define('LL706_LINEUP_SERVICE_KEY', 'replace-with-a-long-random-secret');
```

Its requests use `X-LL706-Lineup-Key` over HTTPS. This authenticates **n8n to WordPress**; it does not authenticate a member to AskBruno. The current app chat sends a user number but no proof that the caller owns it. Until chat authentication is added, do not use these routes to answer questions from private individual Work Logs or to expose private photo bytes to chat callers.

The service lists active, unprocessed Work Log photos with their source `user_id`, `work_date`, and `shift`; downloads one private JPEG for extraction; and saves the result in WordPress lineup and unit tables. The source Work Log date and shift are used when the sheet does not show them. A conflicting printed date or shift cannot be published without review. `published` results require at least one unit; `needs_review`, `not_lineup`, and `retry` results are not searchable. The workflow should classify uncertain handwriting as `needs_review`, not invent a unit or name. Review tooling and the n8n workflow are separate follow-up work.

Example extraction body (the omitted printed date falls back to the source Work Log date):

```json
{
  "status": "published",
  "printed_date": null,
  "printed_shift": "1st",
  "raw_text": "5433 ...",
  "extraction_version": "lineup-v1",
  "units": [
    {
      "unit_number": "5433",
      "cover_figure": "1/F",
      "work_to_do": "Inspect air leak",
      "assigned_names": ["Example Name"]
    }
  ]
}
```

Duplicate handling checks identical photo bytes for the same date and shift, then a normalized hash of the extracted rows. Different content for the same date and shift is retained as a separate revision. Each published result has a stable `lineup_key` for later Qdrant indexing; n8n must reconcile the `/lineup-service/index` active keys with vector points after photo deletion or reprocessing. The chat query endpoint requires `user_id` and returns only published lineup rows uploaded by that user, backed by active photos and Work Logs. This number does **not** verify ownership of the chat request or establish which person on the sheet is that member. No written Work Log notes or tasks are returned.

Photos remain in private file storage. A published lineup result includes a `photo_url` that opens a WordPress login-protected viewer for approved members. The app may need the member to sign in on the website before the image opens. Unpublished Work Log photos are never available through this viewer.

### Private Work Log query

The separate `/work-log-query/entries` endpoint gives n8n read-only access to a requested member's backed-up written Work Logs and active photo metadata. Configure a different secret in protected server configuration:

```php
define('LL706_WORK_LOG_QUERY_SERVICE_KEY', 'replace-with-a-different-long-random-secret');
```

Requests use `X-LL706-Work-Log-Query-Key` over HTTPS and require a positive WordPress `user_id`. The key authenticates n8n to WordPress. The route returns only active entries and their active photo references for the requested user; photo bytes are never in the JSON response. Optional `work_date`, `date_from`, `date_to`, `shift`, and `keyword` filters narrow the results; `before_id` and `limit` paginate them. Keyword filtering is a substring search of Work Log text, so an agent must verify the exact unit or name in returned entries before answering. Mobile apps fetch selected photo bytes through the existing owner-only bearer-token photo endpoint.

The current AskBruno chat workflow uses the app-supplied `metadata.unionUser.userId` as the requested ID. That value identifies which records to read but is not independently authenticated by this service. It does not create a vector copy; WordPress remains the source of truth.

For local Work Log query checks, run `php tests/work-log-query-smoke.php`. A WordPress staging site is still needed to verify service routes and photo viewing before deployment.

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
| `/work-log-photos` | `GET` | List the authenticated member's active `photos` and `deleted_photos` UUID/entry pairs for active Work Logs. | `Authorization: Bearer <token>` header |
| `/work-log/{entry_uuid}/photos` | `POST` | Upload one JPEG to a Work Log owned by the authenticated member. Repeating the same UUID and bytes is idempotent. | Bearer token; multipart `photo`, `photo_uuid`, optional `filename`, `caption`, `created_at` |
| `/work-log/{entry_uuid}/photos/{photo_uuid}` | `GET` | Download the authenticated member's private JPEG. | `Authorization: Bearer <token>` header |
| `/work-log/{entry_uuid}/photos/{photo_uuid}` | `DELETE` | Remove one backed-up photo and queue file cleanup. | `Authorization: Bearer <token>` header |
| `/lineup-service/photos` | `GET` | List active photos not yet classified or marked for retry. | `X-LL706-Lineup-Key`; optional `after_id`, `limit` (max 100) |
| `/lineup-service/photos/{photo_id}` | `GET` | Download the active private JPEG for server-side extraction. | `X-LL706-Lineup-Key` |
| `/lineup-service/photos/{photo_id}/extraction` | `PUT` | Store classification and extracted lineup rows in WordPress. | `X-LL706-Lineup-Key`; JSON `status`, optional `printed_date`, `printed_shift`, `raw_text`, `extraction_version`, `units` |
| `/lineup-service/lineups` | `GET` | Return published lineups uploaded by the selected user and member-viewer photo links; no private Work Log text. | `X-LL706-Lineup-Key`; required `user_id`; optional `work_date`, `date_from`, `date_to`, `shift`, `unit`, `after_id`, `limit` |
| `/lineup-service/index` | `GET` | Page the active published lineup corpus for Qdrant reconciliation, including duplicate uploads with the same `lineup_key`. | `X-LL706-Lineup-Key`; optional `after_id`, `limit` |
| `/work-log-query/entries` | `GET` | Read active written Work Logs and photo references for a requested WordPress user ID; no photo bytes. | `X-LL706-Work-Log-Query-Key`; required `user_id`; optional `work_date`, `date_from`, `date_to`, `shift`, `keyword`, `before_id`, `limit` (max 100) |
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

### 0.9.27

- Expanded the separately keyed, read-only Work Log query route to accept any valid WordPress user ID and include active photo references with each returned entry. The route excludes deleted entries and photo bytes; the supplied user ID selects records without authenticating the chat caller.

### 0.9.26

- Added a separate, read-only Work Log query route limited to one configured test member and protected by its own service key. It excludes deleted entries and photos and remains unsuitable for member chat until caller identity is verified.

### 0.9.25

- Quoted the lineup unit `row_number` column so its table can be created on MariaDB versions where the name is reserved.

### 0.9.24

- Added service-key-only endpoints and WordPress tables to prepare backed-up Work Log photos for lineup extraction and search.
- Stored lineup rows by source Work Log date and shift, with printed-value conflict checks and duplicate fingerprints. Individual Work Log text remains outside the lineup service.

### 0.9.23

- Kept photo deletion records and exposed them to compatible clients so deleted photos stay deleted across devices.
- Serialized per-member photo uploads to enforce count and byte limits during simultaneous requests.

### 0.9.22

- Documented the single Work Log backup setting, private photo storage, access limits, retention, and deletion behavior in the plugin Overview tab and GitHub README.
- Clarified the Work Log Photos admin tab for compatible app builds.

### 0.9.21

- Moved LL706 Auth API from Settings to its own top-level WordPress admin menu.
- Added private, per-member Work Log photo storage routes and an admin storage-health tab. Photos remain local-only in existing mobile app releases until the apps adopt the routes.

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
