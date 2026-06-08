# LL706 Auth API

WordPress plugin that powers the LL706 mobile and web apps with hardened login, membership approval, and JSON Web Token (JWT) authentication. It also exposes an admin workflow for approving or blocking a member’s access without touching their WordPress account.

## Requirements

- WordPress 6.0 or higher
- Tested up to WordPress 7.0
- PHP 7.4 or higher

## Features

- Login endpoint that accepts username or email and issues signed JWT tokens with configurable TTLs per role.
- Member self‑registration endpoint that collects profile meta (Ultimate Member compatible) and queues the account for manual approval.
- `/me` endpoint that validates tokens, rehydrates Ultimate Member fields, and returns the current user payload.
- Public `/dashboard-form` endpoint for a remote-controlled Ask Bruno dashboard form card.
- Per-user work-log storage with authenticated create, read, update, and soft-delete endpoints.
- Admin settings page with separate Dashboard Form Card, Login History, Overview, and Settings tabs.
- Per-user app login summary showing each member’s latest successful app login, token status, IP, and user agent.
- CSV export for the last-login summary.
- Automatic login log retention cleanup with a configurable number of days.
- Per‑user access controls rendered on the user edit screen and the Users table (Approve / Block / Auto) so admins can toggle app access in one click.
- Automatic integration with Ultimate Member approvals via the `um_after_user_is_approved` hook.
- Automatic plugin updates from the `main` branch of `https://github.com/jcjason12108-alt/LL706-Auth-API/` using Plugin Update Checker.

## Installation

1. Copy `LL706 Auth API.php` into `wp-content/plugins/ll706-auth-api/` (or clone this repository there).
2. In the WordPress dashboard, activate **LL706 Auth API** under *Plugins → Installed Plugins*.
3. Open *Settings → LL706 Auth API* to configure the JWT secret, approval meta key, dashboard form card, token lifetimes, and login log retention. Changing the secret or the “Force Logout” button invalidates existing tokens.
4. Use the *Overview* tab for built-in documentation and the *Login History* tab for recent app login activity and CSV export.

## REST API

All routes live under the namespace `ll706/v1`.

| Endpoint | Method | Description | Expected Params |
| --- | --- | --- | --- |
| `/login` | `POST` | Authenticate an existing member, vet approval status, and return a JWT payload. | `username` (or email), `password` |
| `/register` | `POST` | Create a pending member and store Ultimate Member profile meta. | `username`, `password`, `email`, `first_name`, `last_name`, `local_number`, `email_opt_in` plus optional address/phone/card fields |
| `/dashboard-form` | `GET` | Return the public dashboard form-card configuration for the app. | None |
| `/me` | `GET` | Validate a token and return the hydrated user payload. | `Authorization: Bearer <token>` header |
| `/work-log` | `GET` | Return the authenticated member’s non-deleted work-log entries. | `Authorization: Bearer <token>` header |
| `/work-log` | `POST` | Create a work-log entry for the authenticated member. | `Authorization: Bearer <token>` header plus `work_date`, `shift` (`1st`, `2nd`, or `3rd`; numeric `1`, `2`, and `3` are normalized), `work_items`, and optional `entry_uuid`, `doubled`, `supervisor`, `worked_with`, `notes` |
| `/work-log/{entry_uuid}` | `PUT` | Update one work-log entry owned by the authenticated member. | `Authorization: Bearer <token>` header plus the same body fields as create |
| `/work-log/{entry_uuid}` | `DELETE` | Soft-delete one work-log entry owned by the authenticated member. | `Authorization: Bearer <token>` header |

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
- GitHub update checks require the repository root to contain `LL706 Auth API.php` directly, not inside an extra nested plugin folder.
- The updater does not use a GitHub token because this repository is public. If GitHub returns 403 on a live site, manually upload the latest ZIP once so the installed updater no longer sends stale server tokens.
- To force all tokens invalid, bump the `token_version` option from the settings page.
- Need to bulk approve legacy members? With WP‑CLI you can run:  
  `wp user list --field=ID | xargs -I % wp user meta update % ll706_approved 1`
  (replace `ll706_approved` if you changed the meta key).

## Changelog

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
