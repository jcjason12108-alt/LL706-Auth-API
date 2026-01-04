<?php
/**
 * Plugin Name: LL706 Auth API
 * Description: WordPress login + manual approval + JWT auth for LL706 mobile/web apps.
 * Version: 0.6.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Jason Cox
 * Author URI: https://github.com/jcjason12108-alt
 */

if (!defined('ABSPATH')) exit;

/**
 * =====================================================
 * SETTINGS (Admin UI)
 * =====================================================
 */
add_action('admin_menu', function () {
  add_options_page(
    'LL706 Auth API',
    'LL706 Auth API',
    'manage_options',
    'll706-auth-api',
    'll706_auth_api_settings_page'
  );
});

add_action('admin_init', function () {
  register_setting('ll706_auth_api', 'll706_auth_api_options', [
    'type' => 'array',
    'sanitize_callback' => 'll706_auth_api_sanitize_options',
    'default' => []
  ]);
});

add_action('show_user_profile', 'll706_auth_api_render_user_access_controls');
add_action('edit_user_profile', 'll706_auth_api_render_user_access_controls');
add_action('personal_options_update', 'll706_auth_api_save_user_access_controls');
add_action('edit_user_profile_update', 'll706_auth_api_save_user_access_controls');
add_filter('manage_users_columns', 'll706_auth_api_add_users_column');
add_filter('manage_users_custom_column', 'll706_auth_api_render_users_column', 10, 3);
add_action('admin_post_ll706_toggle_access', 'll706_auth_api_handle_toggle_access');
add_action('admin_notices', 'll706_auth_api_access_notice');

function ll706_auth_api_defaults() {
  return [
    'jwt_secret'        => '',
    'local_value'       => '706',
    'approved_meta_key' => 'll706_approved',
    'token_ttl_admin'   => 12 * HOUR_IN_SECONDS,
    'token_ttl_exec'    => 12 * HOUR_IN_SECONDS,
    'token_ttl_member'  => 24 * HOUR_IN_SECONDS,
    'token_version'     => 1,
  ];
}

function ll706_auth_api_get_options() {
  $saved = get_option('ll706_auth_api_options', []);
  return array_merge(ll706_auth_api_defaults(), is_array($saved) ? $saved : []);
}

function ll706_auth_api_get_user_access_status($user_id) {
  $opts = ll706_auth_api_get_options();
  $raw  = get_user_meta($user_id, $opts['approved_meta_key'], true);

  if ($raw === '' || $raw === null) {
    return 'auto';
  }

  $normalized = strtolower((string) $raw);
  if ((int) $raw === 1 || in_array($normalized, ['1', 'true', 'yes', 'approved'], true)) {
    return 'approved';
  }

  return 'pending';
}

function ll706_auth_api_is_user_approved($user_id) {
  return ll706_auth_api_get_user_access_status($user_id) !== 'pending';
}

function ll706_auth_api_update_user_access_status($user_id, $status) {
  $opts = ll706_auth_api_get_options();
  $meta_key = $opts['approved_meta_key'];

  switch ($status) {
    case 'approved':
      update_user_meta($user_id, $meta_key, 1);
      break;
    case 'pending':
      update_user_meta($user_id, $meta_key, 0);
      break;
    case 'auto':
    default:
      delete_user_meta($user_id, $meta_key);
      break;
  }
}

function ll706_auth_api_add_users_column($columns) {
  $columns['ll706_app_access'] = 'LL706 App';
  return $columns;
}

function ll706_auth_api_render_users_column($output, $column_name, $user_id) {
  if ($column_name !== 'll706_app_access') return $output;

  $status = ll706_auth_api_get_user_access_status($user_id);
  $labels = [
    'approved' => 'Approved',
    'pending'  => 'Blocked',
    'auto'     => 'Auto',
  ];

  $html = '<strong>' . esc_html($labels[$status] ?? ucfirst($status)) . '</strong>';

  if (current_user_can('manage_options')) {
    $links = [];
    if ($status !== 'approved') {
      $links[] = ll706_auth_api_build_access_link($user_id, 'approved', 'Approve');
    }
    if ($status !== 'pending') {
      $links[] = ll706_auth_api_build_access_link($user_id, 'pending', 'Block');
    }
    if ($status !== 'auto') {
      $links[] = ll706_auth_api_build_access_link($user_id, 'auto', 'Auto');
    }

    if (!empty($links)) {
      $html .= '<br /><span class="ll706-access-actions">' . implode(' | ', $links) . '</span>';
    }
  }

  return $html;
}

function ll706_auth_api_build_access_link($user_id, $state, $label) {
  $url = wp_nonce_url(
    add_query_arg([
      'action'  => 'll706_toggle_access',
      'user_id' => $user_id,
      'state'   => $state,
    ], admin_url('admin-post.php')),
    'll706_toggle_access_' . $user_id
  );

  return '<a href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
}

function ll706_auth_api_handle_toggle_access() {
  if (!current_user_can('manage_options')) {
    wp_die('You do not have permission to perform this action.');
  }

  $user_id = isset($_GET['user_id']) ? absint($_GET['user_id']) : 0;
  $state   = isset($_GET['state']) ? sanitize_text_field(wp_unslash($_GET['state'])) : '';

  if (!$user_id || !in_array($state, ['approved', 'pending', 'auto'], true)) {
    wp_safe_redirect(admin_url('users.php'));
    exit;
  }

  check_admin_referer('ll706_toggle_access_' . $user_id);

  ll706_auth_api_update_user_access_status($user_id, $state);

  $redirect = wp_get_referer();
  if (!$redirect) {
    $redirect = admin_url('users.php');
  }
  $redirect = add_query_arg('ll706_access_updated', $state, $redirect);

  wp_safe_redirect($redirect);
  exit;
}

function ll706_auth_api_access_notice() {
  if (!current_user_can('manage_options')) return;
  if (!isset($_GET['ll706_access_updated'])) return;

  $screen = function_exists('get_current_screen') ? get_current_screen() : null;
  if ($screen && $screen->id !== 'users') return;

  $state = sanitize_text_field(wp_unslash($_GET['ll706_access_updated']));
  $labels = [
    'approved' => 'Approved',
    'pending'  => 'Blocked',
    'auto'     => 'Auto',
  ];

  echo '<div class="notice notice-success is-dismissible"><p>';
  echo esc_html(sprintf('LL706 app access updated: %s.', $labels[$state] ?? $state));
  echo '</p></div>';
}

function ll706_auth_api_sanitize_options($opts) {
  $defaults = ll706_auth_api_defaults();
  $out = $defaults;

  if (!is_array($opts)) return $defaults;

  $out['jwt_secret']        = trim((string)($opts['jwt_secret'] ?? ''));
  $out['local_value']       = sanitize_text_field((string)($opts['local_value'] ?? '706'));
  $out['approved_meta_key'] = sanitize_key((string)($opts['approved_meta_key'] ?? 'll706_approved'));

  $min = 5 * MINUTE_IN_SECONDS;
  $max = 30 * DAY_IN_SECONDS;

  foreach (['token_ttl_admin','token_ttl_exec','token_ttl_member'] as $k) {
    $val = intval($opts[$k] ?? $defaults[$k]);
    $out[$k] = max($min, min($max, $val));
  }

  $out['token_version'] = max(1, intval($opts['token_version'] ?? 1));

  return $out;
}

function ll706_auth_api_settings_page() {
  if (!current_user_can('manage_options')) return;
  $opts = ll706_auth_api_get_options();

  if (isset($_POST['ll706_force_logout']) && check_admin_referer('ll706_force_logout')) {
    $opts['token_version']++;
    update_option('ll706_auth_api_options', $opts);
    echo '<div class="updated"><p><strong>All tokens invalidated.</strong></p></div>';
  }
?>
<div class="wrap">
<h1>LL706 Auth API</h1>

<p>This plugin provides secure login for the LL706 mobile app and API clients.</p>

<h2>Security Settings</h2>
<form method="post" action="options.php">
<?php settings_fields('ll706_auth_api'); ?>
<table class="form-table">

<tr>
<th>JWT Secret</th>
<td>
<input type="text" name="ll706_auth_api_options[jwt_secret]" value="<?php echo esc_attr($opts['jwt_secret']); ?>" class="regular-text" />
<p class="description">
Secret used to sign login tokens. Changing this logs out all users.
Leave blank to use WordPress’s built-in security key.
</p>
</td>
</tr>

<tr>
<th>Approval Meta Key</th>
<td>
<input type="text" name="ll706_auth_api_options[approved_meta_key]" value="<?php echo esc_attr($opts['approved_meta_key']); ?>" class="regular-text" />
<p class="description">
User meta key that must be set to <code>1</code> before login is allowed.
</p>
</td>
</tr>

<tr>
<th>Local Identifier</th>
<td>
<input type="text" name="ll706_auth_api_options[local_value]" value="<?php echo esc_attr($opts['local_value']); ?>" class="regular-text" />
<p class="description">
Identifier embedded in login tokens. Change this if you reuse the plugin for another Local.
</p>
</td>
</tr>

</table>

<h2>Token Lifetime</h2>
<table class="form-table">

<tr>
<th>Admin Token TTL (seconds)</th>
<td><input type="number" name="ll706_auth_api_options[token_ttl_admin]" value="<?php echo esc_attr($opts['token_ttl_admin']); ?>" /></td>
</tr>

<tr>
<th>Executive Board / General Chairman TTL</th>
<td><input type="number" name="ll706_auth_api_options[token_ttl_exec]" value="<?php echo esc_attr($opts['token_ttl_exec']); ?>" /></td>
</tr>

<tr>
<th>Member Token TTL</th>
<td><input type="number" name="ll706_auth_api_options[token_ttl_member]" value="<?php echo esc_attr($opts['token_ttl_member']); ?>" /></td>
</tr>

</table>

<?php submit_button(); ?>
</form>

<hr />

<h2>Emergency</h2>
<form method="post">
<?php wp_nonce_field('ll706_force_logout'); ?>
<p>
<button class="button button-secondary" name="ll706_force_logout">
Invalidate All Tokens (Force Logout)
</button>
</p>
<p class="description">
Immediately logs out all users on all devices.
</p>
</form>

</div>
<?php
}

function ll706_auth_api_render_user_access_controls($user) {
  if (!current_user_can('manage_options')) return;

  $opts = ll706_auth_api_get_options();
  $meta_key = $opts['approved_meta_key'];
  $status = ll706_auth_api_get_user_access_status($user->ID);
?>
  <h2>LL706 App Access</h2>
  <table class="form-table" role="presentation">
    <tr>
      <th scope="row">Mobile App Access</th>
      <td>
        <label>
          <input type="radio" name="ll706_approved_status" value="approved" <?php checked($status, 'approved'); ?> />
          Approved (allow login)
        </label>
        <br />
        <label>
          <input type="radio" name="ll706_approved_status" value="pending" <?php checked($status, 'pending'); ?> />
          Pending / Blocked (deny login)
        </label>
        <br />
        <label>
          <input type="radio" name="ll706_approved_status" value="auto" <?php checked($status, 'auto'); ?> />
          Auto (legacy default; treated as approved until set)
        </label>
        <p class="description">Stored under user meta key <code><?php echo esc_html($meta_key); ?></code>.</p>
      </td>
    </tr>
  </table>
<?php
}

function ll706_auth_api_save_user_access_controls($user_id) {
  if (!current_user_can('manage_options')) return;
  if (!isset($_POST['ll706_approved_status'])) return;

  $status = sanitize_text_field(wp_unslash($_POST['ll706_approved_status']));
  ll706_auth_api_update_user_access_status($user_id, $status);
}

/**
 * =====================================================
 * REST ROUTES
 * =====================================================
 */
add_action('rest_api_init', function () {
  register_rest_route('ll706/v1', '/login', [
    'methods'  => 'POST',
    'callback' => 'll706_auth_login',
    'permission_callback' => '__return_true',
  ]);
  register_rest_route('ll706/v1', '/register', [
    'methods'  => 'POST',
    'callback' => 'll706_auth_register',
    'permission_callback' => '__return_true',
  ]);

  register_rest_route('ll706/v1', '/me', [
    'methods'  => 'GET',
    'callback' => 'll706_auth_me',
    'permission_callback' => '__return_true',
  ]);
});

/**
 * =====================================================
 * JWT HELPERS
 * =====================================================
 */
function ll706_jwt_secret() {
  $opts = ll706_auth_api_get_options();
  return $opts['jwt_secret'] !== '' ? $opts['jwt_secret'] : AUTH_KEY;
}

function ll706_base64url_encode($data) {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function ll706_base64url_decode($data) {
  return base64_decode(strtr($data, '-_', '+/'));
}

function ll706_jwt_encode(array $payload) {
  $header = ['alg' => 'HS256', 'typ' => 'JWT'];
  $segments = [
    ll706_base64url_encode(json_encode($header)),
    ll706_base64url_encode(json_encode($payload))
  ];
  $sig = hash_hmac('sha256', implode('.', $segments), ll706_jwt_secret(), true);
  $segments[] = ll706_base64url_encode($sig);
  return implode('.', $segments);
}

function ll706_jwt_decode($jwt) {
  $parts = explode('.', $jwt);
  if (count($parts) !== 3) throw new Exception('Malformed token');

  [$h, $p, $s] = $parts;
  $check = hash_hmac('sha256', "$h.$p", ll706_jwt_secret(), true);

  if (!hash_equals($check, ll706_base64url_decode($s))) {
    throw new Exception('Invalid signature');
  }

  $payload = json_decode(ll706_base64url_decode($p), true);
  if (!$payload) throw new Exception('Invalid payload');
  if (time() > intval($payload['exp'])) throw new Exception('Token expired');

  return $payload;
}

/**
 * =====================================================
 * LOGIN + ME
 * =====================================================
 */
function ll706_auth_login(WP_REST_Request $req) {
  $opts = ll706_auth_api_get_options();

  $raw_username = trim((string)$req->get_param('username'));
  $password     = (string)$req->get_param('password');

  if ($raw_username === '' || $password === '') {
    return new WP_REST_Response([
      'ok' => false,
      'error' => 'missing_credentials',
      'message' => 'Username and password are required.'
    ], 400);
  }

  // Allow login by email OR username (hardened)
  $username = $raw_username;
  if (is_email($username)) {
    $user_obj = get_user_by('email', $username);

    if (!$user_obj) {
      return new WP_REST_Response([
        'ok' => false,
        'error' => 'invalid_login',
        'message' => 'Invalid username or password.'
      ], 401);
    }

    $username = $user_obj->user_login;
  }

  $user = wp_authenticate($username, $password);

  if (is_wp_error($user)) {
    return new WP_REST_Response([
      'ok' => false,
      'error' => 'invalid_login',
      'message' => 'Invalid username or password.'
    ], 401);
  }

  $approval_meta_key = $opts['approved_meta_key'];

  // Administrators are always approved
  if (in_array('administrator', (array) $user->roles, true)) {
      update_user_meta($user->ID, $approval_meta_key, 1);
  } else {
      if (!ll706_auth_api_is_user_approved($user->ID)) {
          return new WP_REST_Response([
              'ok' => false,
              'error' => 'not_approved',
              'message' => 'Your account is pending approval.'
          ], 403);
      }
  }

  $role = $user->roles[0] ?? 'subscriber';
  $ttl  = ($role === 'administrator') ? $opts['token_ttl_admin']
        : (($role === 'executive_board' || $role === 'general_chairman') ? $opts['token_ttl_exec']
        : $opts['token_ttl_member']);

  $now = time();
  $payload = [
    'iss' => get_site_url(),
    'iat' => $now,
    'exp' => $now + $ttl,
    'ver' => $opts['token_version'],
    'data'=>[
      'user_id'=>$user->ID,
      'username'=>$user->user_login,
      'name'=>$user->display_name,
      'email'=>$user->user_email,
      'role'=>$role,
      'local'=>$opts['local_value'],
      'approved'=>true
    ]
  ];

  // Fetch Ultimate Member profile fields (read-only) as in /me
  $meta = get_user_meta($user->ID);

  // Ultimate Member profile fields (READ-ONLY)
  $payload['data']['first_name']   = $meta['first_name'][0] ?? null;
  $payload['data']['last_name']    = $meta['last_name'][0] ?? null;
  $payload['data']['email']        = $user->user_email;
  $payload['data']['username']     = $user->user_login;

  $payload['data']['address']      = $meta['Address'][0] ?? null;
  $payload['data']['city']         = $meta['Address_10'][0] ?? null;
  $payload['data']['state_zip']    = $meta['Address_10_11'][0] ?? null;
  $payload['data']['zip']          = $meta['Address_10_11_16'][0] ?? null;

  $payload['data']['local_number'] = $meta['LodgeNumber'][0] ?? null;

  // Employee number (explicitly excluded from app use)
  // $payload['data']['employee_number'] = $meta['cardNumber_12'][0] ?? null;

  // Contact fields (allowed)
  // Mobile phone
  $payload['data']['phone'] =
    $meta['phone_number_17'][0]
    ?? null;

  // Home phone
  $payload['data']['home_phone'] =
    $meta['phone_number'][0]
    ?? null;

  $payload['data']['card_number']  = $meta['cardNumber'][0] ?? null;
  $payload['data']['email_opt_in'] = !empty($meta['EmailOptin'][0]);

  return new WP_REST_Response([
    'ok'=>true,
    'token'=>ll706_jwt_encode($payload),
    'expires_at'=>$payload['exp'],
    'user'=>$payload['data']
  ],200);
}

/**
 * =====================================================
 * REGISTER (Pending Approval)
 * =====================================================
 */
function ll706_auth_register(WP_REST_Request $req) {
  $opts = ll706_auth_api_get_options();

  // Validate required fields (matches iOS RegistrationView)
  $required = [
    'username',
    'password',
    'email',
    'first_name',
    'last_name',
    'local_number',
    'email_opt_in',
  ];

  foreach ($required as $field) {
    $val = $req->get_param($field);
    if ($val === null || $val === '') {
      return new WP_REST_Response([
        'ok' => false,
        'error' => 'missing_fields',
        'message' => "Missing required field: {$field}"
      ], 400);
    }
  }

  $username = sanitize_user($req->get_param('username'), true);
  $email    = sanitize_email($req->get_param('email'));
  $password = (string) $req->get_param('password');

  if (username_exists($username) || email_exists($email)) {
    return new WP_REST_Response([
      'ok' => false,
      'error' => 'user_exists',
      'message' => 'An account with this username or email already exists.'
    ], 409);
  }

  $user_id = wp_create_user($username, $password, $email);
  if (is_wp_error($user_id)) {
    return new WP_REST_Response([
      'ok' => false,
      'error' => 'create_failed',
      'message' => $user_id->get_error_message()
    ], 500);
  }

  // Set base role + LL706 approval flag
  $user = get_user_by('id', $user_id);
  $user->set_role('subscriber');
  update_user_meta($user_id, $opts['approved_meta_key'], 0);

  // Core WP profile
  wp_update_user([
    'ID'         => $user_id,
    'first_name' => sanitize_text_field($req->get_param('first_name')),
    'last_name'  => sanitize_text_field($req->get_param('last_name')),
  ]);

  // Normalize email opt-in
  $email_opt_in = in_array(
    strtolower((string) $req->get_param('email_opt_in')),
    ['1','true','yes','on'],
    true
  ) ? '1' : '0';

  // Ultimate Member profile meta (REST-safe)
  $meta_map = [
    'Address'          => 'address',
    'Address_10'       => 'city',
    'Address_10_11'    => 'state',
    'Address_10_11_16' => 'zip',
    'LodgeNumber'      => 'local_number',
    'phone_number'     => 'home_phone',
    'phone_number_17'  => 'cellPhone',
    'cardNumber'       => 'cardNumber',
    'cardNumber_12'    => 'employeeNumber',
  ];

  foreach ($meta_map as $meta_key => $param) {
    if ($req->get_param($param) !== null) {
      update_user_meta(
        $user_id,
        $meta_key,
        sanitize_text_field($req->get_param($param))
      );
    }
  }

  update_user_meta($user_id, 'EmailOptin', $email_opt_in);

  // Force Ultimate Member Pending Review (UM expects specific status strings)
  // Using UM's canonical value prevents the admin UI from showing "undefined".
  $um_pending = 'awaiting_admin_review';
  update_user_meta($user_id, 'account_status', $um_pending);
  update_user_meta($user_id, 'um_account_status', $um_pending);
  // Extra compatibility keys (harmless if UM ignores them)
  update_user_meta($user_id, 'um_user_account_status', $um_pending);
  update_user_meta($user_id, 'um_account_status_cache', $um_pending);

  /**
   * Registration hook (automation, notifications, roster sync)
   */
  do_action('ll706_user_registered', [
    'user_id'      => $user_id,
    'username'     => $username,
    'email'        => $email,
    'email_opt_in' => $email_opt_in,
  ]);

  // =====================================================
  // Notify Ultimate Member (email + workflows)
  // =====================================================
  if ( function_exists('um_fetch_user') ) {
    um_fetch_user($user_id);

    /**
     * Trigger UM registration flow
     */
    do_action('um_after_user_register', $user_id);

    /**
     * Explicitly notify UM the user is pending admin review
     */
    do_action('um_after_user_is_pending', $user_id);
  }

  return new WP_REST_Response([
    'ok'      => true,
    // Keep app-facing status stable
    'status'  => 'pending',
    // Also return the UM status we set (useful for debugging; app should ignore unknown fields)
    'um_status' => $um_pending,
    'message' => 'Registration submitted. Pending administrator approval.'
  ], 200);
}

function ll706_auth_me(WP_REST_Request $req) {
  $auth = $req->get_header('authorization');
  if (!$auth || !preg_match('/Bearer\s(\S+)/', $auth, $m)) {
    return new WP_REST_Response(['ok' => false, 'error' => 'missing_token'], 401);
  }

  try {
    $payload = ll706_jwt_decode($m[1]);
  } catch (Exception $e) {
    return new WP_REST_Response(['ok' => false, 'error' => 'invalid_token'], 401);
  }

  $opts = ll706_auth_api_get_options();
  if ((int) $payload['ver'] !== (int) $opts['token_version']) {
    return new WP_REST_Response(['ok' => false, 'error' => 'invalidated'], 401);
  }

  $user_id = intval($payload['data']['user_id']);
  $meta = get_user_meta($user_id);

  // Base identity from token
  $user = $payload['data'];

  // Ultimate Member profile fields (READ-ONLY)
  $user['first_name']   = $meta['first_name'][0] ?? null;
  $user['last_name']    = $meta['last_name'][0] ?? null;
  $user['email']        = $user['email'] ?? null;
  $user['username']     = $user['username'] ?? null;

  $user['address']      = $meta['Address'][0] ?? null;
  $user['city']         = $meta['Address_10'][0] ?? null;
  $user['state_zip']    = $meta['Address_10_11'][0] ?? null;
  $user['zip']          = $meta['Address_10_11_16'][0] ?? null;

  $user['local_number'] = $meta['LodgeNumber'][0] ?? null;

  // Employee number intentionally excluded
  // $user['employee_number'] = $meta['cardNumber_12'][0] ?? null;

  // Contact fields (allowed)
  // Mobile phone
  $user['phone'] =
    $meta['phone_number_17'][0]
    ?? null;

  // Home phone
  $user['home_phone'] =
    $meta['phone_number'][0]
    ?? null;

  $user['card_number']  = $meta['cardNumber'][0] ?? null;
  $user['email_opt_in'] = !empty($meta['EmailOptin'][0]);

  return new WP_REST_Response([
    'ok' => true,
    'user' => $user,
    'expires_at' => $payload['exp']
  ], 200);
}

/**
 * Sync Ultimate Member approval → App approval
 * When a user is approved in Ultimate Member,
 * automatically mark them approved for app login.
 */
add_action('um_after_user_is_approved', function ($user_id) {
    $opts = ll706_auth_api_get_options();

    update_user_meta(
        $user_id,
        $opts['approved_meta_key'],
        1
    );
});
