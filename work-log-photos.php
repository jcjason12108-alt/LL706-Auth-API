<?php
/**
 * Private, per-member Work Log photo backup for AskBruno.
 *
 * The storage directory is deliberately not created inside wp-content/uploads.
 * Set LL706_WORK_LOG_PHOTO_DIR to an existing, writable directory outside the
 * web server's document root before enabling uploads.
 */

if (!defined('ABSPATH')) exit;

if (!defined('LL706_WORK_LOG_PHOTO_DB_VERSION')) {
  define('LL706_WORK_LOG_PHOTO_DB_VERSION', '1.0.0');
}

if (!defined('LL706_WORK_LOG_PHOTO_MAX_BYTES')) {
  define('LL706_WORK_LOG_PHOTO_MAX_BYTES', 5 * 1024 * 1024);
}

if (!defined('LL706_WORK_LOG_PHOTO_MAX_PER_ENTRY')) {
  define('LL706_WORK_LOG_PHOTO_MAX_PER_ENTRY', 20);
}

if (!defined('LL706_WORK_LOG_PHOTO_MAX_USER_BYTES')) {
  define('LL706_WORK_LOG_PHOTO_MAX_USER_BYTES', 1024 * 1024 * 1024);
}

add_action('rest_api_init', 'll706_auth_photo_register_routes');
add_filter('rest_pre_serve_request', 'll706_auth_photo_serve_private_file', 10, 4);
add_action('ll706_auth_api_daily_cleanup', 'll706_auth_photo_purge_deleted');
add_action('delete_user', 'll706_auth_photo_delete_for_user');

function ll706_auth_photo_table_name() {
  global $wpdb;
  return $wpdb->prefix . 'll706_work_log_photos';
}

function ll706_auth_photo_maybe_setup_table() {
  if (get_option('ll706_work_log_photo_db_version', '') !== LL706_WORK_LOG_PHOTO_DB_VERSION) {
    ll706_auth_photo_setup_table();
  }
}

function ll706_auth_photo_setup_table() {
  global $wpdb;

  require_once ABSPATH . 'wp-admin/includes/upgrade.php';
  $table = ll706_auth_photo_table_name();
  $charset_collate = $wpdb->get_charset_collate();
  $sql = "CREATE TABLE {$table} (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    user_id bigint(20) unsigned NOT NULL,
    entry_uuid char(36) NOT NULL,
    photo_uuid char(36) NOT NULL,
    filename varchar(191) NOT NULL,
    caption text NULL,
    byte_count bigint(20) unsigned NOT NULL,
    sha256 char(64) NOT NULL,
    created_at datetime NOT NULL,
    deleted_at datetime NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY user_photo_uuid (user_id, photo_uuid),
    KEY user_entry_deleted (user_id, entry_uuid, deleted_at)
  ) {$charset_collate};";

  dbDelta($sql);
  if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table) {
    update_option('ll706_work_log_photo_db_version', LL706_WORK_LOG_PHOTO_DB_VERSION, false);
  }
}

/**
 * Return only a directory that already exists outside WordPress and webroot.
 * The server administrator must still confirm that the host does not expose it
 * through another virtual host and that backups include it.
 */
function ll706_auth_photo_storage_root($needs_write = false) {
  $configured = defined('LL706_WORK_LOG_PHOTO_DIR')
    ? trim((string) LL706_WORK_LOG_PHOTO_DIR)
    : '';

  if ($configured === '') {
    return new WP_Error('photo_storage_not_configured', 'Private photo storage is not configured.', ['status' => 503]);
  }

  if (!is_dir($configured) || is_link($configured)) {
    return new WP_Error('photo_storage_unavailable', 'Private photo storage is unavailable.', ['status' => 503]);
  }

  $root = realpath($configured);
  if ($root === false || !is_readable($root) || ($needs_write && !is_writable($root))) {
    return new WP_Error('photo_storage_unavailable', 'Private photo storage is unavailable.', ['status' => 503]);
  }

  $public_roots = [ABSPATH];
  if (!empty($_SERVER['DOCUMENT_ROOT'])) {
    $public_roots[] = (string) $_SERVER['DOCUMENT_ROOT'];
  }

  foreach ($public_roots as $public_root) {
    $public_real = realpath($public_root);
    if ($public_real !== false && ($root === $public_real || strpos($root, rtrim($public_real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0)) {
      return new WP_Error('photo_storage_public', 'Photo storage must be outside the public web directory.', ['status' => 503]);
    }
  }

  return $root;
}

function ll706_auth_photo_path($root, $photo_uuid) {
  return $root . DIRECTORY_SEPARATOR . strtolower($photo_uuid) . '.jpg';
}

function ll706_auth_photo_valid_uuid($value) {
  return is_string($value) && wp_is_uuid($value) ? strtolower($value) : '';
}

function ll706_auth_photo_owned_entry($user_id, $entry_uuid) {
  global $wpdb;
  $table = ll706_auth_work_logs_table_name();
  return (bool) $wpdb->get_var($wpdb->prepare(
    "SELECT id FROM {$table} WHERE user_id = %d AND entry_uuid = %s AND deleted_at IS NULL LIMIT 1",
    (int) $user_id,
    $entry_uuid
  ));
}

function ll706_auth_photo_error($code, $message, $status) {
  return ll706_auth_error_response(new WP_Error($code, $message, ['status' => $status]));
}

function ll706_auth_photo_authorized_user(WP_REST_Request $request) {
  $payload = ll706_auth_get_current_user_from_request($request);
  return is_wp_error($payload) ? $payload : (int) $payload['data']['user_id'];
}

function ll706_auth_photo_entry_from_request(WP_REST_Request $request, $user_id) {
  $entry_uuid = ll706_auth_photo_valid_uuid((string) $request['entry_uuid']);
  if ($entry_uuid === '' || !ll706_auth_photo_owned_entry($user_id, $entry_uuid)) {
    return new WP_Error('work_log_not_found', 'Work Log entry was not found.', ['status' => 404]);
  }
  return $entry_uuid;
}

function ll706_auth_photo_format_row($row) {
  return [
    'photo_uuid' => (string) $row['photo_uuid'],
    'entry_uuid' => (string) $row['entry_uuid'],
    'filename' => (string) $row['filename'],
    'caption' => (string) ($row['caption'] ?? ''),
    'byte_count' => (int) $row['byte_count'],
    'sha256' => (string) $row['sha256'],
    'created_at' => gmdate('c', strtotime((string) $row['created_at'] . ' UTC')),
  ];
}

function ll706_auth_photo_register_routes() {
  // WP_REST_Response is available when rest_api_init runs.
  if (!class_exists('LL706_Auth_Private_Photo_Response', false)) {
    class LL706_Auth_Private_Photo_Response extends WP_REST_Response {
      public $file_path;
      public $download_name;

      public function __construct($file_path, $download_name) {
        parent::__construct(null, 200);
        $this->file_path = $file_path;
        $this->download_name = $download_name;
      }
    }
  }

  register_rest_route('ll706/v1', '/work-log-photos', [
    'methods' => 'GET',
    'callback' => 'll706_auth_photo_list',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);

  register_rest_route('ll706/v1', '/work-log/(?P<entry_uuid>[a-zA-Z0-9-]+)/photos', [
    'methods' => 'POST',
    'callback' => 'll706_auth_photo_upload',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);

  register_rest_route('ll706/v1', '/work-log/(?P<entry_uuid>[a-zA-Z0-9-]+)/photos/(?P<photo_uuid>[a-zA-Z0-9-]+)', [
    'methods' => 'GET',
    'callback' => 'll706_auth_photo_download',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);

  register_rest_route('ll706/v1', '/work-log/(?P<entry_uuid>[a-zA-Z0-9-]+)/photos/(?P<photo_uuid>[a-zA-Z0-9-]+)', [
    'methods' => 'DELETE',
    'callback' => 'll706_auth_photo_delete',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);
}

function ll706_auth_photo_list(WP_REST_Request $request) {
  global $wpdb;
  $user_id = ll706_auth_photo_authorized_user($request);
  if (is_wp_error($user_id)) return ll706_auth_error_response($user_id);
  $root = ll706_auth_photo_storage_root();
  if (is_wp_error($root)) return ll706_auth_error_response($root);

  $photos = ll706_auth_photo_table_name();
  $logs = ll706_auth_work_logs_table_name();
  $rows = $wpdb->get_results($wpdb->prepare(
    "SELECT p.* FROM {$photos} p INNER JOIN {$logs} w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid WHERE p.user_id = %d AND p.deleted_at IS NULL AND w.deleted_at IS NULL ORDER BY p.created_at, p.id",
    $user_id
  ), ARRAY_A);

  if ($rows === null) {
    return ll706_auth_photo_error('photo_list_failed', 'Unable to list Work Log photos.', 500);
  }

  $response = new WP_REST_Response(['ok' => true, 'photos' => array_map('ll706_auth_photo_format_row', $rows)], 200);
  $response->header('Cache-Control', 'private, no-store');
  return $response;
}

function ll706_auth_photo_upload(WP_REST_Request $request) {
  global $wpdb;
  $user_id = ll706_auth_photo_authorized_user($request);
  if (is_wp_error($user_id)) return ll706_auth_error_response($user_id);

  $entry_uuid = ll706_auth_photo_entry_from_request($request, $user_id);
  if (is_wp_error($entry_uuid)) return ll706_auth_error_response($entry_uuid);

  $photo_uuid = ll706_auth_photo_valid_uuid((string) $request->get_param('photo_uuid'));
  if ($photo_uuid === '') return ll706_auth_photo_error('invalid_photo_uuid', 'A valid photo UUID is required.', 400);

  $root = ll706_auth_photo_storage_root(true);
  if (is_wp_error($root)) return ll706_auth_error_response($root);

  $files = $request->get_file_params();
  $upload = isset($files['photo']) ? $files['photo'] : null;
  if (!is_array($upload) || (int) ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
    return ll706_auth_photo_error('photo_upload_missing', 'A JPEG photo upload is required.', 400);
  }

  $size = (int) ($upload['size'] ?? 0);
  $source = isset($upload['tmp_name']) ? (string) $upload['tmp_name'] : '';
  if ($size < 1 || $size > LL706_WORK_LOG_PHOTO_MAX_BYTES || !is_uploaded_file($source)) {
    return ll706_auth_photo_error('photo_upload_invalid', 'Photo upload is invalid or too large.', 400);
  }

  $image = @getimagesize($source);
  if (!is_array($image) || ($image[2] ?? null) !== IMAGETYPE_JPEG || $image[0] < 1 || $image[1] < 1 || max($image[0], $image[1]) > 3000) {
    return ll706_auth_photo_error('photo_type_invalid', 'Photo must be a JPEG no larger than 3000 pixels on its longest side.', 400);
  }

  $sha256 = hash_file('sha256', $source);
  if ($sha256 === false) return ll706_auth_photo_error('photo_upload_invalid', 'Unable to verify the photo.', 400);

  $table = ll706_auth_photo_table_name();
  $existing = $wpdb->get_row($wpdb->prepare(
    "SELECT * FROM {$table} WHERE user_id = %d AND photo_uuid = %s LIMIT 1",
    $user_id,
    $photo_uuid
  ), ARRAY_A);
  $repair_existing = false;
  if ($existing) {
    if ($existing['entry_uuid'] === $entry_uuid && empty($existing['deleted_at']) && hash_equals((string) $existing['sha256'], $sha256)) {
      if (!is_link(ll706_auth_photo_path($root, $photo_uuid)) && is_file(ll706_auth_photo_path($root, $photo_uuid))) {
        return new WP_REST_Response(['ok' => true, 'photo' => ll706_auth_photo_format_row($existing)], 200);
      }
      $repair_existing = true;
    } else {
      return ll706_auth_photo_error('photo_uuid_conflict', 'This photo UUID is already in use.', 409);
    }
  }

  if (!$repair_existing) {
    $entry_count = (int) $wpdb->get_var($wpdb->prepare(
      "SELECT COUNT(*) FROM {$table} WHERE user_id = %d AND entry_uuid = %s AND deleted_at IS NULL",
      $user_id,
      $entry_uuid
    ));
    if ($entry_count >= LL706_WORK_LOG_PHOTO_MAX_PER_ENTRY) {
      return ll706_auth_photo_error('photo_entry_limit', 'This Work Log entry has reached its photo limit.', 413);
    }

    $user_bytes = (int) $wpdb->get_var($wpdb->prepare(
      "SELECT COALESCE(SUM(byte_count), 0) FROM {$table} WHERE user_id = %d AND deleted_at IS NULL",
      $user_id
    ));
    if ($user_bytes + $size > LL706_WORK_LOG_PHOTO_MAX_USER_BYTES) {
      return ll706_auth_photo_error('photo_storage_limit', 'This account has reached its photo storage limit.', 413);
    }
  }

  $filename = sanitize_file_name((string) $request->get_param('filename'));
  if ($filename === '' || !preg_match('/\.jpe?g$/i', $filename)) {
    $filename = $photo_uuid . '.jpg';
  }
  $filename = substr($filename, 0, 191);
  $caption = sanitize_text_field((string) $request->get_param('caption'));
  $caption = substr($caption, 0, 1000);
  $created_at_input = (string) $request->get_param('created_at');
  $created_at_timestamp = $created_at_input !== '' ? strtotime($created_at_input) : false;
  $created_at = $created_at_timestamp !== false
    ? gmdate('Y-m-d H:i:s', $created_at_timestamp)
    : current_time('mysql', true);

  $destination = ll706_auth_photo_path($root, $photo_uuid);
  if (file_exists($destination)) {
    return ll706_auth_photo_error('photo_storage_conflict', 'Photo storage conflict.', 409);
  }

  $staging = tempnam($root, '.ll706-photo-');
  if ($staging === false || realpath(dirname($staging)) !== $root || !move_uploaded_file($source, $staging)) {
    if ($staging !== false) @unlink($staging);
    return ll706_auth_photo_error('photo_store_failed', 'Unable to store the photo.', 500);
  }

  // Exclusive create claims the UUID path without replacing another upload.
  $previous_umask = umask(0077);
  $output = @fopen($destination, 'x');
  umask($previous_umask);
  if ($output === false) {
    @unlink($staging);
    return file_exists($destination)
      ? ll706_auth_photo_error('photo_storage_conflict', 'Photo storage conflict.', 409)
      : ll706_auth_photo_error('photo_store_failed', 'Unable to store the photo.', 500);
  }
  @chmod($destination, 0600);
  $input = @fopen($staging, 'rb');
  $copied = $input !== false ? stream_copy_to_stream($input, $output) : false;
  if ($input !== false) fclose($input);
  fclose($output);
  @unlink($staging);
  $stored_hash = $copied === $size ? hash_file('sha256', $destination) : false;
  if ($copied !== $size || $stored_hash === false || !hash_equals($sha256, $stored_hash)) {
    @unlink($destination);
    return ll706_auth_photo_error('photo_store_failed', 'Unable to store the photo.', 500);
  }

  if ($repair_existing) {
    return new WP_REST_Response(['ok' => true, 'photo' => ll706_auth_photo_format_row($existing)], 200);
  }

  $inserted = $wpdb->insert($table, [
    'user_id' => $user_id,
    'entry_uuid' => $entry_uuid,
    'photo_uuid' => $photo_uuid,
    'filename' => $filename,
    'caption' => $caption,
    'byte_count' => $size,
    'sha256' => $sha256,
    'created_at' => $created_at,
  ], ['%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s']);

  if ($inserted === false) {
    @unlink($destination);
    return ll706_auth_photo_error('photo_record_failed', 'Unable to record the photo.', 500);
  }

  $row = $wpdb->get_row($wpdb->prepare(
    "SELECT * FROM {$table} WHERE user_id = %d AND photo_uuid = %s LIMIT 1",
    $user_id,
    $photo_uuid
  ), ARRAY_A);
  if (!$row) return ll706_auth_photo_error('photo_record_failed', 'Unable to confirm the photo record.', 500);
  return new WP_REST_Response(['ok' => true, 'photo' => ll706_auth_photo_format_row($row)], 201);
}

function ll706_auth_photo_find_owned_row(WP_REST_Request $request, $user_id, $entry_uuid) {
  global $wpdb;
  $photo_uuid = ll706_auth_photo_valid_uuid((string) $request['photo_uuid']);
  if ($photo_uuid === '') return null;
  $table = ll706_auth_photo_table_name();
  return $wpdb->get_row($wpdb->prepare(
    "SELECT * FROM {$table} WHERE user_id = %d AND entry_uuid = %s AND photo_uuid = %s AND deleted_at IS NULL LIMIT 1",
    $user_id,
    $entry_uuid,
    $photo_uuid
  ), ARRAY_A);
}

function ll706_auth_photo_download(WP_REST_Request $request) {
  $user_id = ll706_auth_photo_authorized_user($request);
  if (is_wp_error($user_id)) return ll706_auth_error_response($user_id);
  $entry_uuid = ll706_auth_photo_entry_from_request($request, $user_id);
  if (is_wp_error($entry_uuid)) return ll706_auth_error_response($entry_uuid);
  $row = ll706_auth_photo_find_owned_row($request, $user_id, $entry_uuid);
  if (!$row) return ll706_auth_photo_error('photo_not_found', 'Photo was not found.', 404);

  $root = ll706_auth_photo_storage_root();
  if (is_wp_error($root)) return ll706_auth_error_response($root);
  $path = ll706_auth_photo_path($root, $row['photo_uuid']);
  if (is_link($path) || !is_file($path) || !is_readable($path)) {
    return ll706_auth_photo_error('photo_file_missing', 'Photo file is unavailable.', 503);
  }

  // A dedicated response type prevents a JSON route from reflecting file paths.
  return new LL706_Auth_Private_Photo_Response($path, $row['filename']);
}

function ll706_auth_photo_serve_private_file($served, $result, $request, $server) {
  if ($served || !($result instanceof LL706_Auth_Private_Photo_Response)) return $served;

  $path = $result->file_path;
  if (is_link($path) || !is_file($path) || !is_readable($path)) {
    status_header(503);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo wp_json_encode(['ok' => false, 'error' => 'photo_file_missing', 'message' => 'Photo file is unavailable.']);
    return true;
  }

  $filename = str_replace(['"', "\r", "\n"], '', basename($result->download_name));
  header('Content-Type: image/jpeg');
  header('Content-Disposition: attachment; filename="' . $filename . '"');
  header('Content-Length: ' . filesize($path));
  header('Cache-Control: private, no-store, max-age=0');
  header('X-Content-Type-Options: nosniff');
  readfile($path);
  return true;
}

function ll706_auth_photo_delete(WP_REST_Request $request) {
  global $wpdb;
  $user_id = ll706_auth_photo_authorized_user($request);
  if (is_wp_error($user_id)) return ll706_auth_error_response($user_id);
  $entry_uuid = ll706_auth_photo_entry_from_request($request, $user_id);
  if (is_wp_error($entry_uuid)) return ll706_auth_error_response($entry_uuid);
  $row = ll706_auth_photo_find_owned_row($request, $user_id, $entry_uuid);
  if (!$row) return ll706_auth_photo_error('photo_not_found', 'Photo was not found.', 404);

  $table = ll706_auth_photo_table_name();
  $updated = $wpdb->update($table, ['deleted_at' => current_time('mysql', true)], ['id' => (int) $row['id'], 'deleted_at' => null], ['%s'], ['%d', '%s']);
  if ($updated !== 1) return ll706_auth_photo_error('photo_delete_failed', 'Unable to delete the photo.', 500);

  ll706_auth_photo_purge_deleted();
  return new WP_REST_Response(['ok' => true], 200);
}

function ll706_auth_photo_delete_for_entry($user_id, $entry_uuid) {
  global $wpdb;
  $table = ll706_auth_photo_table_name();
  $wpdb->update($table, ['deleted_at' => current_time('mysql', true)], [
    'user_id' => (int) $user_id,
    'entry_uuid' => $entry_uuid,
    'deleted_at' => null,
  ], ['%s'], ['%d', '%s', '%s']);
  ll706_auth_photo_purge_deleted();
}

function ll706_auth_photo_delete_for_user($user_id) {
  global $wpdb;
  $table = ll706_auth_photo_table_name();
  $wpdb->update($table, ['deleted_at' => current_time('mysql', true)], [
    'user_id' => (int) $user_id,
    'deleted_at' => null,
  ], ['%s'], ['%d', '%s']);
  ll706_auth_photo_purge_deleted();
}

function ll706_auth_photo_purge_deleted() {
  global $wpdb;
  $root = ll706_auth_photo_storage_root(true);
  if (is_wp_error($root)) return;

  $photos = ll706_auth_photo_table_name();
  $logs = ll706_auth_work_logs_table_name();
  // Repair deletion markers if a Work Log was removed while storage was down.
  $wpdb->query("UPDATE {$photos} p LEFT JOIN {$logs} w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid SET p.deleted_at = UTC_TIMESTAMP() WHERE p.deleted_at IS NULL AND (w.id IS NULL OR w.deleted_at IS NOT NULL)");

  $rows = $wpdb->get_results("SELECT id, photo_uuid FROM {$photos} WHERE deleted_at IS NOT NULL ORDER BY id LIMIT 100", ARRAY_A);
  foreach ((array) $rows as $row) {
    $path = ll706_auth_photo_path($root, $row['photo_uuid']);
    if (is_file($path) && !@unlink($path)) continue;
    $wpdb->delete($photos, ['id' => (int) $row['id']], ['%d']);
  }
}

function ll706_auth_photo_render_admin_tab() {
  if (!current_user_can('manage_options')) return;
  global $wpdb;
  $table = ll706_auth_photo_table_name();
  $stats = $wpdb->get_row("SELECT COUNT(*) AS total, COALESCE(SUM(byte_count), 0) AS bytes FROM {$table} WHERE deleted_at IS NULL", ARRAY_A);
  $pending = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table} WHERE deleted_at IS NOT NULL");
  $root = ll706_auth_photo_storage_root(true);
  $status = is_wp_error($root) ? $root->get_error_message() : 'Ready';
  ?>
  <h2>Work Log Photo Backup</h2>
  <p>Photos are stored outside the public website directory. This page shows storage health and totals; it does not display members' photos.</p>
  <table class="widefat striped" style="max-width: 700px;"><tbody>
    <tr><th>Storage</th><td><?php echo esc_html($status); ?></td></tr>
    <tr><th>Backed-up photos</th><td><?php echo esc_html(number_format_i18n((int) ($stats['total'] ?? 0))); ?></td></tr>
    <tr><th>Photo bytes</th><td><?php echo esc_html(size_format((int) ($stats['bytes'] ?? 0))); ?></td></tr>
    <tr><th>Pending deletions</th><td><?php echo esc_html(number_format_i18n($pending)); ?></td></tr>
  </tbody></table>
  <p>Set <code>LL706_WORK_LOG_PHOTO_DIR</code> to an existing, writable directory outside the web root. Include that directory in the site's backups. Uploads remain unavailable until storage is ready. The mobile apps must be updated before they will send photos to this API.</p>
  <?php
}
