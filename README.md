# LL706 Auth API

WordPress plugin that powers the LL706 mobile and web apps with hardened login, membership approval, and JSON Web Token (JWT) authentication. It also exposes a lightweight admin workflow for approving or blocking a member’s access without touching their WordPress account.  [oai_citation:0‡README.md](sediment://file_000000004188722f981ee830f6cbc2c8)

---

## Requirements

- WordPress 6.0 or higher  
- PHP 7.4 or higher  

---

## Features

- Login endpoint accepting **username or email**, issuing signed JWT tokens with configurable TTLs per role  
- Member **self-registration endpoint** that collects profile meta (Ultimate Member compatible) and queues accounts for manual approval  
- `/me` endpoint that validates tokens, rehydrates Ultimate Member fields, and returns the current user payload  
- Admin settings page to configure:
  - JWT secret  
  - Approval meta key  
  - Local identifier  
  - Token lifetimes  
  - Global logout (token invalidation)  
- Per-user access controls rendered in:
  - User edit screen  
  - Users table (Approve / Block / Auto)  
- Automatic integration with Ultimate Member approvals via the `um_after_user_is_approved` hook  

---

## Installation

1. Copy `LL706 Auth API.php` into:

wp-content/plugins/ll706-auth-api/

*(or clone this repository into that directory)*

2. In the WordPress dashboard, activate **LL706 Auth API** under  
**Plugins → Installed Plugins**

3. Visit **Settings → LL706 Auth API** to configure:
- JWT secret  
- Approval meta key  
- Token lifetimes  

> Changing the JWT secret or clicking **Force Logout** immediately invalidates all existing tokens.

---

## REST API

All routes live under the namespace:

ll706/v1

### Endpoints

| Endpoint    | Method | Description                                                         | Expected Params |
|------------|--------|---------------------------------------------------------------------|-----------------|
| `/login`   | POST   | Authenticate an existing member and return a JWT payload            | `username` (or email), `password` |
| `/register`| POST   | Create a pending member and store Ultimate Member profile meta      | `username`, `password`, `email`, `first_name`, `last_name`, `local_number`, `email_opt_in` + optional address/phone/card fields |
| `/me`      | GET    | Validate a token and return the hydrated user payload               | `Authorization: Bearer <token>` |

### Response Format

```json
// success
{
  "ok": true,
  "token": "jwt_token_here",
  "expires_at": 1234567890,
  "user": {}
}

// error
{
  "ok": false,
  "error": "not_approved",
  "message": "Your account is pending approval."
}


⸻

Admin Access Controls

Users Table

Users → All Users includes an LL706 App column with inline actions:
	•	Approve – sets approval meta to 1
	•	Block – sets approval meta to 0 (login denied)
	•	Auto – removes the meta key (legacy state; treated as approved until blocked)

User Profile Screen

The same controls are available on individual user profile pages.
Saving the profile updates the approval meta immediately.

The meta key used is configurable in the settings page, allowing alignment with your existing data model.

⸻

Ultimate Member Integration
	•	Registration stores the canonical awaiting_admin_review status across Ultimate Member’s expected meta keys
	•	When Ultimate Member approves a member via:

um_after_user_is_approved

the plugin automatically sets the LL706 approval meta to 1, enabling app logins immediately.

⸻

Development

Linting

php -l "LL706 Auth API.php"

Token Invalidation
	•	Bump the token_version option in the settings page to invalidate all active JWTs

Bulk Approval (WP-CLI)

wp user list --field=ID | xargs -I % wp user meta update % ll706_approved 1

Replace ll706_approved if you changed the approval meta key.

⸻

License

