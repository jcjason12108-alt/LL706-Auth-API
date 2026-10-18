<?php
/** Android Restore Credentials. The private key stays with Android; only its public key lives here. */
if (!defined('ABSPATH')) exit;

const LL706_RESTORE_SCHEMA_VERSION = '1';
const LL706_RESTORE_RP_ID = 'www.iamll706.org';
const LL706_RESTORE_PLAY_CERT_SHA256 = 'A9:DD:6C:C5:CA:0F:1F:55:14:B1:27:8B:42:93:EB:4E:38:C7:41:D5:DE:7E:1C:14:AF:24:F4:0B:5D:0E:D1:8E';

function ll706_restore_ready() {
  return PHP_VERSION_ID >= 80000 && extension_loaded('openssl');
}

function ll706_restore_table_name() {
  global $wpdb;
  return $wpdb->prefix . 'll706_restore_credentials';
}

add_action('init', 'll706_restore_maybe_create_table');
function ll706_restore_maybe_create_table() {
  if (get_option('ll706_restore_schema_version') === LL706_RESTORE_SCHEMA_VERSION) return;
  global $wpdb;
  require_once ABSPATH . 'wp-admin/includes/upgrade.php';
  $table = ll706_restore_table_name();
  $sql = "CREATE TABLE {$table} (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    user_id bigint(20) unsigned NOT NULL,
    credential_hash char(64) NOT NULL,
    credential_id varchar(512) NOT NULL,
    public_key text NOT NULL,
    sign_count bigint(20) unsigned NOT NULL DEFAULT 0,
    token_version bigint(20) unsigned NOT NULL,
    created_at datetime NOT NULL,
    last_used_at datetime NULL,
    PRIMARY KEY (id),
    UNIQUE KEY credential_hash (credential_hash),
    KEY user_id (user_id)
  ) " . $wpdb->get_charset_collate() . ';';
  dbDelta($sql);
  update_option('ll706_restore_schema_version', LL706_RESTORE_SCHEMA_VERSION, false);
}

add_action('rest_api_init', 'll706_restore_register_routes');
function ll706_restore_register_routes() {
  $routes = [
    '/restore-credential/register-options' => ['ll706_restore_register_options', 'll706_auth_api_require_bearer_token'],
    '/restore-credential/register' => ['ll706_restore_register', 'll706_auth_api_require_bearer_token'],
    '/restore-credential/auth-options' => ['ll706_restore_auth_options', '__return_true'],
    '/restore-credential/auth' => ['ll706_restore_auth', '__return_true'],
    '/restore-credential/revoke' => ['ll706_restore_revoke', 'll706_auth_api_require_bearer_token'],
  ];
  foreach ($routes as $route => $handlers) {
    register_rest_route('ll706/v1', $route, [
      'methods' => 'POST',
      'callback' => $handlers[0],
      'permission_callback' => $handlers[1],
    ]);
  }
}

function ll706_restore_unavailable() {
  return ll706_auth_api_json_error('restore_unavailable', 'Device sign-in restore is unavailable.', 503);
}

function ll706_restore_webauthn() {
  if (!ll706_restore_ready()) return null;
  spl_autoload_register(static function ($class) {
    $prefix = 'lbuchs\\WebAuthn\\';
    if (strpos($class, $prefix) !== 0) return;
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/vendor/lbuchs-webauthn/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) require_once $path;
  });
  $wa = new \lbuchs\WebAuthn\WebAuthn('AskBruno', LL706_RESTORE_RP_ID, ['none', 'packed'], true);
  $hashes = [LL706_RESTORE_PLAY_CERT_SHA256];
  if (defined('LL706_RESTORE_EXTRA_CERT_SHA256') && is_array(LL706_RESTORE_EXTRA_CERT_SHA256)) {
    $hashes = array_merge($hashes, LL706_RESTORE_EXTRA_CERT_SHA256);
  }
  $allowed = [];
  foreach ($hashes as $fingerprint) {
    $hex = preg_replace('/[^0-9A-Fa-f]/', '', (string) $fingerprint);
    if (strlen($hex) === 64) {
      $allowed[] = rtrim(strtr(base64_encode(hex2bin($hex)), '+/', '-_'), '=');
    }
  }
  $wa->addAndroidKeyHashes($allowed);
  return $wa;
}

function ll706_restore_b64url_decode($value) {
  if (!is_string($value) || strlen($value) > 16384 || !preg_match('/^[A-Za-z0-9_-]+$/', $value)) return false;
  return base64_decode(strtr($value, '-_', '+/'), true);
}

function ll706_restore_flow($kind, $data) {
  $id = bin2hex(random_bytes(16));
  set_transient('ll706_restore_' . $kind . '_' . $id, $data, 5 * MINUTE_IN_SECONDS);
  return $id;
}

function ll706_restore_rate_limited($bucket, $limit) {
  $ip = ll706_auth_api_get_request_ip_for_wordfence();
  $key = 'll706_restore_rate_' . $bucket . '_' . hash('sha256', $ip ?: 'unknown');
  $count = (int) get_transient($key);
  if ($count >= $limit) return true;
  set_transient($key, $count + 1, MINUTE_IN_SECONDS);
  return false;
}

function ll706_restore_consume_flow($kind, $id) {
  if (!is_string($id) || !preg_match('/^[a-f0-9]{32}$/', $id)) return false;
  $key = 'll706_restore_' . $kind . '_' . $id;
  $data = get_transient($key);
  delete_transient($key);
  return $data;
}

function ll706_restore_credential_json(WP_REST_Request $req) {
  $json = $req->get_param('credential_json');
  if (!is_string($json) || strlen($json) > 32768) return false;
  $credential = json_decode($json, true);
  if (!is_array($credential) || ($credential['type'] ?? '') !== 'public-key' || !is_array($credential['response'] ?? null)) return false;
  return $credential;
}

function ll706_restore_android_origin_valid($client_data_json) {
  $client = json_decode($client_data_json, true);
  if (!is_array($client) || !is_string($client['origin'] ?? null)) return false;
  if (isset($client['androidPackageName']) && $client['androidPackageName'] !== 'org.iamll706.askbruno') return false;
  $origin = $client['origin'];
  $prefix = 'android:apk-key-hash:';
  if (strpos($origin, $prefix) !== 0) return false;
  $hash = substr($origin, strlen($prefix));
  $fingerprints = [LL706_RESTORE_PLAY_CERT_SHA256];
  if (defined('LL706_RESTORE_EXTRA_CERT_SHA256') && is_array(LL706_RESTORE_EXTRA_CERT_SHA256)) {
    $fingerprints = array_merge($fingerprints, LL706_RESTORE_EXTRA_CERT_SHA256);
  }
  foreach ($fingerprints as $fingerprint) {
    $hex = preg_replace('/[^0-9A-Fa-f]/', '', (string) $fingerprint);
    if (strlen($hex) === 64 && hash_equals(rtrim(strtr(base64_encode(hex2bin($hex)), '+/', '-_'), '='), $hash)) return true;
  }
  return false;
}

function ll706_restore_register_options(WP_REST_Request $req) {
  if (!ll706_restore_ready()) return ll706_restore_unavailable();
  if (ll706_restore_rate_limited('register', 30)) return ll706_auth_api_json_error('restore_rate_limited', 'Try again later.', 429);
  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) return $payload;
  $user = get_user_by('id', (int) $payload['data']['user_id']);
  if (!$user) return ll706_auth_api_json_error('invalid_user', 'Account unavailable.', 401);
  $wa = ll706_restore_webauthn();
  $args = $wa->getCreateArgs(hash('sha256', 'll706-user-' . $user->ID, true), $user->user_login, $user->display_name, 60, true, false, null);
  $args->publicKey->attestation = 'none';
  unset($args->publicKey->extensions);
  $flow = ll706_restore_flow('register', [
    'user_id' => (int) $user->ID,
    'challenge' => base64_encode($wa->getChallenge()->getBinaryString()),
  ]);
  return ['ok' => true, 'flow_id' => $flow, 'options_json' => wp_json_encode($args->publicKey)];
}

function ll706_restore_register(WP_REST_Request $req) {
  if (!ll706_restore_ready()) return ll706_restore_unavailable();
  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) return $payload;
  $flow = ll706_restore_consume_flow('register', $req->get_param('flow_id'));
  $credential = ll706_restore_credential_json($req);
  if (!is_array($flow) || (int) $flow['user_id'] !== (int) $payload['data']['user_id'] || !$credential) {
    return ll706_auth_api_json_error('invalid_restore_registration', 'Invalid restore registration.', 400);
  }
  $response = $credential['response'];
  $client_data = ll706_restore_b64url_decode($response['clientDataJSON'] ?? null);
  $attestation = ll706_restore_b64url_decode($response['attestationObject'] ?? null);
  if ($client_data === false || $attestation === false || !ll706_restore_android_origin_valid($client_data)) {
    return ll706_auth_api_json_error('invalid_restore_registration', 'Invalid restore registration.', 400);
  }
  try {
    $data = ll706_restore_webauthn()->processCreate($client_data, $attestation, base64_decode($flow['challenge']), false, false);
  } catch (Throwable $e) {
    return ll706_auth_api_json_error('invalid_restore_registration', 'Invalid restore registration.', 400);
  }
  $id = rtrim(strtr(base64_encode($data->credentialId), '+/', '-_'), '=');
  $provided_id = (string) ($credential['rawId'] ?? $credential['id'] ?? '');
  if (!hash_equals($id, $provided_id)) return ll706_auth_api_json_error('invalid_restore_registration', 'Invalid restore registration.', 400);
  global $wpdb;
  $ok = $wpdb->replace(ll706_restore_table_name(), [
    'user_id' => (int) $flow['user_id'],
    'credential_hash' => hash('sha256', $data->credentialId),
    'credential_id' => $id,
    'public_key' => $data->credentialPublicKey,
    'sign_count' => max(0, (int) $data->signatureCounter),
    'token_version' => (int) ll706_auth_api_get_options()['token_version'],
    'created_at' => current_time('mysql', true),
  ]);
  if (!$ok) return ll706_restore_unavailable();
  return ['ok' => true];
}

function ll706_restore_auth_options(WP_REST_Request $req) {
  if (!ll706_restore_ready()) return ll706_restore_unavailable();
  if (ll706_restore_rate_limited('options', 30)) return ll706_auth_api_json_error('restore_rate_limited', 'Try again later.', 429);
  $wa = ll706_restore_webauthn();
  $args = $wa->getGetArgs([], 60, false, false, false, false, true, false);
  $flow = ll706_restore_flow('auth', ['challenge' => base64_encode($wa->getChallenge()->getBinaryString())]);
  return ['ok' => true, 'flow_id' => $flow, 'options_json' => wp_json_encode($args->publicKey)];
}

function ll706_restore_auth(WP_REST_Request $req) {
  if (!ll706_restore_ready()) return ll706_restore_unavailable();
  if (ll706_restore_rate_limited('auth', 20)) return ll706_auth_api_json_error('restore_rate_limited', 'Try again later.', 429);
  $flow = ll706_restore_consume_flow('auth', $req->get_param('flow_id'));
  $credential = ll706_restore_credential_json($req);
  if (!is_array($flow) || !$credential) return ll706_auth_api_json_error('invalid_restore_credential', 'Sign-in restore failed.', 401);
  $id = (string) ($credential['rawId'] ?? $credential['id'] ?? '');
  $raw_id = ll706_restore_b64url_decode($id);
  $response = $credential['response'];
  $client_data = ll706_restore_b64url_decode($response['clientDataJSON'] ?? null);
  $auth_data = ll706_restore_b64url_decode($response['authenticatorData'] ?? null);
  $signature = ll706_restore_b64url_decode($response['signature'] ?? null);
  if ($raw_id === false || $client_data === false || $auth_data === false || $signature === false || !ll706_restore_android_origin_valid($client_data)) {
    return ll706_auth_api_json_error('invalid_restore_credential', 'Sign-in restore failed.', 401);
  }
  global $wpdb;
  $table = ll706_restore_table_name();
  $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE credential_hash = %s", hash('sha256', $raw_id)), ARRAY_A);
  if (!$row || !hash_equals($row['credential_id'], $id)) return ll706_auth_api_json_error('invalid_restore_credential', 'Sign-in restore failed.', 401);
  $opts = ll706_auth_api_get_options();
  if ((int) $row['token_version'] !== (int) $opts['token_version'] || !ll706_auth_api_is_user_approved((int) $row['user_id'])) {
    return ll706_auth_api_json_error('restore_access_denied', 'Account access unavailable.', 403);
  }
  $user = get_user_by('id', (int) $row['user_id']);
  if (!$user) return ll706_auth_api_json_error('restore_access_denied', 'Account access unavailable.', 403);
  try {
    $wa = ll706_restore_webauthn();
    // Restore assertions are silent and do not assert user presence.
    $wa->processGet($client_data, $auth_data, $signature, $row['public_key'], base64_decode($flow['challenge']), (int) $row['sign_count'], false, false);
  } catch (Throwable $e) {
    return ll706_auth_api_json_error('invalid_restore_credential', 'Sign-in restore failed.', 401);
  }
  $wpdb->update($table, [
    'sign_count' => max((int) $row['sign_count'], (int) $wa->getSignatureCounter()),
    'last_used_at' => current_time('mysql', true),
  ], ['id' => (int) $row['id']]);
  return ll706_auth_api_issue_token_for_user($user);
}

function ll706_restore_revoke(WP_REST_Request $req) {
  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) return $payload;
  global $wpdb;
  $wpdb->delete(ll706_restore_table_name(), ['user_id' => (int) $payload['data']['user_id']]);
  return ['ok' => true];
}

add_action('wp_set_password', static function ($password, $user_id) {
  global $wpdb;
  $wpdb->delete(ll706_restore_table_name(), ['user_id' => (int) $user_id]);
}, 10, 2);
