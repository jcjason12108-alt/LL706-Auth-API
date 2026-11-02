<?php
/**
 * Server-side lineup extraction storage for backed-up Work Log photos.
 * The mobile chat user number is never treated as authorization here.
 */

if (!defined('ABSPATH')) exit;

define('LL706_LINEUP_DB_VERSION', '1.0.0');

add_action('plugins_loaded', 'll706_lineup_maybe_setup_tables');
add_action('rest_api_init', 'll706_lineup_register_routes');
add_action('admin_post_ll706_lineup_photo', 'll706_lineup_member_photo');
add_action('admin_post_nopriv_ll706_lineup_photo', 'll706_lineup_member_photo_login');
add_action('ll706_auth_photo_deleted', 'll706_lineup_forget_photo');
add_action('ll706_auth_photo_entry_deleted', 'll706_lineup_forget_entry', 10, 2);
add_action('ll706_auth_photo_user_deleted', 'll706_lineup_forget_user');
add_action('ll706_auth_api_daily_cleanup', 'll706_lineup_purge_deleted_sources');

function ll706_lineup_table_name() {
  global $wpdb;
  return $wpdb->prefix . 'll706_lineups';
}

function ll706_lineup_units_table_name() {
  global $wpdb;
  return $wpdb->prefix . 'll706_lineup_units';
}

function ll706_lineup_maybe_setup_tables() {
  if (get_option('ll706_lineup_db_version', '') !== LL706_LINEUP_DB_VERSION) {
    ll706_lineup_setup_tables();
  }
}

function ll706_lineup_setup_tables() {
  global $wpdb;
  require_once ABSPATH . 'wp-admin/includes/upgrade.php';

  $lineups = ll706_lineup_table_name();
  $units = ll706_lineup_units_table_name();
  $charset = $wpdb->get_charset_collate();
  dbDelta("CREATE TABLE {$lineups} (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    photo_id bigint(20) unsigned NOT NULL,
    user_id bigint(20) unsigned NOT NULL,
    entry_uuid char(36) NOT NULL,
    work_date date NOT NULL,
    shift varchar(20) NOT NULL,
    printed_date date NULL,
    printed_shift varchar(20) NULL,
    photo_sha256 char(64) NOT NULL,
    fingerprint char(64) NULL,
    duplicate_of bigint(20) unsigned NULL,
    status varchar(20) NOT NULL,
    raw_text longtext NULL,
    extraction_version varchar(40) NULL,
    updated_at datetime NOT NULL,
    PRIMARY KEY  (id),
    UNIQUE KEY photo_id (photo_id),
    KEY date_shift_status (work_date, shift, status),
    KEY user_status_date (user_id, status, work_date),
    KEY fingerprint (fingerprint),
    KEY exact_photo (photo_sha256, work_date, shift)
  ) {$charset};");
  dbDelta("CREATE TABLE {$units} (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    lineup_id bigint(20) unsigned NOT NULL,
    `row_number` smallint(5) unsigned NOT NULL,
    unit_number varchar(64) NOT NULL,
    cover_figure varchar(120) NULL,
    work_to_do text NULL,
    assigned_names text NULL,
    PRIMARY KEY  (id),
    UNIQUE KEY lineup_row (lineup_id, `row_number`),
    KEY unit_lineup (unit_number, lineup_id)
  ) {$charset};");

  $has_lineups = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $lineups)) === $lineups;
  $has_units = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $units)) === $units;
  if ($has_lineups && $has_units) {
    update_option('ll706_lineup_db_version', LL706_LINEUP_DB_VERSION, false);
  }
}

/** A dedicated n8n secret is required even while member chat auth is deferred. */
function ll706_lineup_require_service_key(WP_REST_Request $request) {
  $key = defined('LL706_LINEUP_SERVICE_KEY') ? (string) LL706_LINEUP_SERVICE_KEY : '';
  if (strlen($key) < 32) {
    return new WP_Error('lineup_service_unavailable', 'Lineup service is not configured.', ['status' => 503]);
  }
  $provided = (string) $request->get_header('x-ll706-lineup-key');
  if ($provided === '' || !hash_equals($key, $provided)) {
    return new WP_Error('lineup_service_forbidden', 'Access denied.', ['status' => 403]);
  }
  if (get_option('ll706_lineup_db_version', '') !== LL706_LINEUP_DB_VERSION) {
    return new WP_Error('lineup_schema_unavailable', 'Lineup storage is unavailable.', ['status' => 503]);
  }
  return true;
}

function ll706_lineup_register_routes() {
  register_rest_route('ll706/v1', '/lineup-service/photos', [
    'methods' => 'GET',
    'callback' => 'll706_lineup_pending_photos',
    'permission_callback' => 'll706_lineup_require_service_key',
  ]);
  register_rest_route('ll706/v1', '/lineup-service/photos/(?P<photo_id>\d+)', [
    'methods' => 'GET',
    'callback' => 'll706_lineup_download_photo',
    'permission_callback' => 'll706_lineup_require_service_key',
  ]);
  register_rest_route('ll706/v1', '/lineup-service/photos/(?P<photo_id>\d+)/extraction', [
    'methods' => 'PUT',
    'callback' => 'll706_lineup_save_extraction',
    'permission_callback' => 'll706_lineup_require_service_key',
  ]);
  register_rest_route('ll706/v1', '/lineup-service/lineups', [
    'methods' => 'GET',
    'callback' => 'll706_lineup_search',
    'permission_callback' => 'll706_lineup_require_service_key',
  ]);
  register_rest_route('ll706/v1', '/lineup-service/index', [
    'methods' => 'GET',
    'callback' => 'll706_lineup_index',
    'permission_callback' => 'll706_lineup_require_service_key',
  ]);
}

function ll706_lineup_active_photo($photo_id) {
  global $wpdb;
  $photos = ll706_auth_photo_table_name();
  $logs = ll706_auth_work_logs_table_name();
  $row = $wpdb->get_row($wpdb->prepare(
    "SELECT p.id, p.user_id, p.entry_uuid, p.photo_uuid, p.filename, p.sha256, p.byte_count, w.work_date, w.shift
       FROM {$photos} p INNER JOIN {$logs} w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid
      WHERE p.id = %d AND p.deleted_at IS NULL AND w.deleted_at IS NULL LIMIT 1",
    (int) $photo_id
  ), ARRAY_A);
  return $row && ll706_auth_photo_valid_uuid((string) $row['photo_uuid']) ? $row : null;
}

function ll706_lineup_pending_photos(WP_REST_Request $request) {
  global $wpdb;
  $photos = ll706_auth_photo_table_name();
  $logs = ll706_auth_work_logs_table_name();
  $lineups = ll706_lineup_table_name();
  $limit = min(100, max(1, (int) ($request->get_param('limit') ?? 25)));
  $after = max(0, (int) $request->get_param('after_id'));
  $rows = $wpdb->get_results($wpdb->prepare(
    "SELECT p.id AS photo_id, p.user_id, p.entry_uuid, p.photo_uuid, p.sha256, p.byte_count, w.work_date, w.shift
       FROM {$photos} p INNER JOIN {$logs} w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid
       LEFT JOIN {$lineups} l ON l.photo_id = p.id
      WHERE p.id > %d AND p.deleted_at IS NULL AND w.deleted_at IS NULL
        AND (l.id IS NULL OR l.status = 'retry' OR l.work_date <> w.work_date OR l.shift <> w.shift)
      ORDER BY p.id ASC LIMIT %d",
    $after, $limit
  ), ARRAY_A);
  if ($rows === null) return new WP_Error('lineup_query_failed', 'Unable to list pending photos.', ['status' => 500]);
  $next = $rows ? (int) $rows[count($rows) - 1]['photo_id'] : $after;
  $response = new WP_REST_Response(['ok' => true, 'photos' => $rows, 'next_after_id' => $next], 200);
  $response->header('Cache-Control', 'private, no-store');
  return $response;
}

function ll706_lineup_download_photo(WP_REST_Request $request) {
  $photo = ll706_lineup_active_photo((int) $request['photo_id']);
  if (!$photo) return new WP_Error('lineup_photo_not_found', 'Photo not found.', ['status' => 404]);
  $root = ll706_auth_photo_storage_root();
  if (is_wp_error($root)) return $root;
  $path = ll706_auth_photo_path($root, $photo['photo_uuid']);
  if (is_link($path) || !is_file($path) || !is_readable($path)) {
    return new WP_Error('lineup_photo_unavailable', 'Photo file is unavailable.', ['status' => 503]);
  }
  return new LL706_Auth_Private_Photo_Response($path, $photo['filename']);
}

function ll706_lineup_valid_date($date) {
  if (!is_string($date) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $date)) return false;
  $parsed = DateTime::createFromFormat('!Y-m-d', $date);
  return $parsed && $parsed->format('Y-m-d') === $date;
}

function ll706_lineup_clean_text($value, $max_length) {
  if (!is_string($value)) return '';
  $clean = sanitize_textarea_field(wp_unslash($value));
  return function_exists('mb_substr') ? mb_substr($clean, 0, $max_length, 'UTF-8') : substr($clean, 0, $max_length);
}

function ll706_lineup_normalized_units($value) {
  if (!is_array($value) || count($value) > 80) return new WP_Error('lineup_invalid_units', 'Expected up to 80 lineup rows.', ['status' => 400]);
  $units = [];
  foreach ($value as $row) {
    if (!is_array($row)) return new WP_Error('lineup_invalid_units', 'Invalid lineup row.', ['status' => 400]);
    $unit = strtoupper(trim(ll706_lineup_clean_text($row['unit_number'] ?? '', 64)));
    $unit = preg_replace('/\s+/', '', $unit);
    if ($unit === '' || !preg_match('/^[A-Z0-9-]{1,64}$/', $unit)) {
      return new WP_Error('lineup_invalid_unit', 'Every row needs a valid unit number.', ['status' => 400]);
    }
    $names = $row['assigned_names'] ?? [];
    if (!is_array($names) || count($names) > 20) return new WP_Error('lineup_invalid_names', 'Invalid assigned names.', ['status' => 400]);
    $names = array_values(array_filter(array_map(static function ($name) {
      return trim(ll706_lineup_clean_text($name, 100));
    }, $names), static function ($name) { return $name !== ''; }));
    $units[] = [
      'unit_number' => $unit,
      'cover_figure' => ll706_lineup_clean_text($row['cover_figure'] ?? '', 120),
      'work_to_do' => ll706_lineup_clean_text($row['work_to_do'] ?? '', 2000),
      'assigned_names' => $names,
    ];
  }
  return $units;
}

function ll706_lineup_fingerprint($units) {
  $parts = [];
  foreach ($units as $unit) {
    $names = $unit['assigned_names'];
    sort($names, SORT_STRING);
    $parts[] = strtolower(preg_replace('/\s+/', ' ', implode('|', [
      $unit['unit_number'], $unit['cover_figure'], $unit['work_to_do'],
      implode(',', $names),
    ])));
  }
  sort($parts, SORT_STRING);
  return hash('sha256', wp_json_encode($parts));
}

function ll706_lineup_key($date, $shift, $fingerprint) {
  return hash('sha256', $date . '|' . $shift . '|' . $fingerprint);
}

function ll706_lineup_units_for_id($lineup_id) {
  global $wpdb;
  $table = ll706_lineup_units_table_name();
  $rows = $wpdb->get_results($wpdb->prepare(
    "SELECT unit_number, cover_figure, work_to_do, assigned_names FROM {$table} WHERE lineup_id = %d ORDER BY `row_number`",
    (int) $lineup_id
  ), ARRAY_A);
  if ($rows === null) return null;
  foreach ($rows as &$row) {
    $names = json_decode((string) $row['assigned_names'], true);
    $row['assigned_names'] = is_array($names) ? $names : [];
  }
  unset($row);
  return $rows;
}

function ll706_lineup_save_extraction(WP_REST_Request $request) {
  global $wpdb;
  $photo = ll706_lineup_active_photo((int) $request['photo_id']);
  if (!$photo) return new WP_Error('lineup_photo_not_found', 'Photo not found.', ['status' => 404]);
  $body = $request->get_json_params();
  if (!is_array($body)) return new WP_Error('lineup_invalid_body', 'Expected a JSON object.', ['status' => 400]);

  $status = isset($body['status']) && is_string($body['status']) ? $body['status'] : '';
  if (!in_array($status, ['published', 'needs_review', 'not_lineup', 'retry'], true)) {
    return new WP_Error('lineup_invalid_status', 'Invalid extraction status.', ['status' => 400]);
  }
  $printed_date = $body['printed_date'] ?? null;
  if ($printed_date !== null && $printed_date !== '' && !ll706_lineup_valid_date($printed_date)) {
    return new WP_Error('lineup_invalid_date', 'printed_date must use YYYY-MM-DD.', ['status' => 400]);
  }
  $printed_date = $printed_date ?: null;
  $printed_shift = null;
  if (isset($body['printed_shift']) && $body['printed_shift'] !== '') {
    $printed_shift = ll706_auth_normalize_work_log_shift($body['printed_shift']);
    if ($printed_shift === '') return new WP_Error('lineup_invalid_shift', 'Invalid printed_shift.', ['status' => 400]);
  }
  $work_date = (string) $photo['work_date'];
  $shift = ll706_auth_normalize_work_log_shift($photo['shift']);
  if ($shift === '') return new WP_Error('lineup_invalid_source', 'Source Work Log has no valid shift.', ['status' => 409]);
  if ($status === 'published' && (($printed_date !== null && $printed_date !== $work_date) || ($printed_shift !== null && $printed_shift !== $shift))) {
    return new WP_Error('lineup_source_mismatch', 'Printed date or shift conflicts with the Work Log; review before publishing.', ['status' => 409]);
  }

  $units = [];
  if ($status === 'published' || $status === 'needs_review') {
    $units = ll706_lineup_normalized_units($body['units'] ?? []);
    if (is_wp_error($units)) return $units;
    if ($status === 'published' && count($units) === 0) {
      return new WP_Error('lineup_empty', 'A published lineup needs at least one unit.', ['status' => 400]);
    }
  }
  $raw_text = ll706_lineup_clean_text($body['raw_text'] ?? '', 30000);
  $version = ll706_lineup_clean_text($body['extraction_version'] ?? '', 40);
  $fingerprint = count($units) ? ll706_lineup_fingerprint($units) : null;
  $lineups = ll706_lineup_table_name();
  $other = null;
  if ($status === 'published') {
    // Exact image bytes win over a slightly different AI reading of that image.
    $other = $wpdb->get_row($wpdb->prepare(
      "SELECT l.id, l.photo_id, l.fingerprint FROM {$lineups} l
         INNER JOIN " . ll706_auth_photo_table_name() . " p ON p.id = l.photo_id
         INNER JOIN " . ll706_auth_work_logs_table_name() . " w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid AND w.work_date = l.work_date AND w.shift = l.shift
        WHERE l.photo_id <> %d AND l.status = 'published' AND l.work_date = %s AND l.shift = %s
          AND l.photo_sha256 = %s AND p.deleted_at IS NULL AND w.deleted_at IS NULL
        ORDER BY l.id LIMIT 1",
      (int) $photo['id'], $work_date, $shift, $photo['sha256']
    ), ARRAY_A);
    if ($other) {
      $canonical_units = ll706_lineup_units_for_id($other['id']);
      if ($canonical_units === null) return new WP_Error('lineup_query_failed', 'Unable to load existing lineup.', ['status' => 500]);
      $units = $canonical_units;
      $fingerprint = $other['fingerprint'];
    } else {
      $other = $wpdb->get_row($wpdb->prepare(
        "SELECT l.id, l.photo_id FROM {$lineups} l
           INNER JOIN " . ll706_auth_photo_table_name() . " p ON p.id = l.photo_id
           INNER JOIN " . ll706_auth_work_logs_table_name() . " w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid AND w.work_date = l.work_date AND w.shift = l.shift
          WHERE l.photo_id <> %d AND l.status = 'published' AND l.work_date = %s AND l.shift = %s
            AND l.fingerprint = %s AND p.deleted_at IS NULL AND w.deleted_at IS NULL
          ORDER BY l.id LIMIT 1",
        (int) $photo['id'], $work_date, $shift, $fingerprint
      ), ARRAY_A);
    }
  }

  $existing = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$lineups} WHERE photo_id = %d", (int) $photo['id']), ARRAY_A);
  $previous_key = $existing && $existing['status'] === 'published' && !empty($existing['fingerprint'])
    ? ll706_lineup_key($existing['work_date'], $existing['shift'], $existing['fingerprint']) : null;
  $now = current_time('mysql', true);
  $values = [
    'photo_id' => (int) $photo['id'],
    'user_id' => (int) $photo['user_id'],
    'entry_uuid' => $photo['entry_uuid'],
    'work_date' => $work_date,
    'shift' => $shift,
    'printed_date' => $printed_date,
    'printed_shift' => $printed_shift,
    'photo_sha256' => $photo['sha256'],
    'fingerprint' => $fingerprint,
    'duplicate_of' => $other ? (int) $other['photo_id'] : null,
    'status' => $status,
    'raw_text' => $raw_text,
    'extraction_version' => $version,
    'updated_at' => $now,
  ];

  if ($wpdb->query('START TRANSACTION') === false) {
    return new WP_Error('lineup_save_failed', 'Unable to start lineup update.', ['status' => 500]);
  }
  if ($existing) {
    $saved = $wpdb->update($lineups, $values, ['id' => (int) $existing['id']]);
    $lineup_id = (int) $existing['id'];
  } else {
    $saved = $wpdb->insert($lineups, $values);
    $lineup_id = (int) $wpdb->insert_id;
  }
  if ($saved === false || $lineup_id < 1) {
    $wpdb->query('ROLLBACK');
    return new WP_Error('lineup_save_failed', 'Unable to save lineup extraction.', ['status' => 500]);
  }
  $unit_table = ll706_lineup_units_table_name();
  if ($wpdb->delete($unit_table, ['lineup_id' => $lineup_id], ['%d']) === false) {
    $wpdb->query('ROLLBACK');
    return new WP_Error('lineup_save_failed', 'Unable to replace lineup rows.', ['status' => 500]);
  }
  foreach ($units as $index => $unit) {
    $ok = $wpdb->insert($unit_table, [
      'lineup_id' => $lineup_id,
      'row_number' => $index + 1,
      'unit_number' => $unit['unit_number'],
      'cover_figure' => $unit['cover_figure'],
      'work_to_do' => $unit['work_to_do'],
      'assigned_names' => wp_json_encode($unit['assigned_names']),
    ], ['%d', '%d', '%s', '%s', '%s', '%s']);
    if (!$ok) {
      $wpdb->query('ROLLBACK');
      return new WP_Error('lineup_save_failed', 'Unable to save lineup rows.', ['status' => 500]);
    }
  }
  if ($wpdb->query('COMMIT') === false) {
    $wpdb->query('ROLLBACK');
    return new WP_Error('lineup_save_failed', 'Unable to commit lineup extraction.', ['status' => 500]);
  }
  $key = $status === 'published' ? ll706_lineup_key($work_date, $shift, $fingerprint) : null;
  $response = new WP_REST_Response([
    'ok' => true,
    'photo_id' => (int) $photo['id'],
    'status' => $status,
    'work_date' => $work_date,
    'shift' => $shift,
    'date_inferred' => $printed_date === null,
    'lineup_key' => $key,
    'previous_lineup_key' => $previous_key !== $key ? $previous_key : null,
    'duplicate_of_photo_id' => $other ? (int) $other['photo_id'] : null,
  ], 200);
  $response->header('Cache-Control', 'private, no-store');
  return $response;
}

/** Return only published lineup facts. Private Work Log notes never enter this route. */
function ll706_lineup_search(WP_REST_Request $request) {
  return ll706_lineup_query($request, true);
}

/** Full active corpus for n8n reconciliation after edits and deletions. */
function ll706_lineup_index(WP_REST_Request $request) {
  return ll706_lineup_query($request, false);
}

function ll706_lineup_query(WP_REST_Request $request, $require_user) {
  global $wpdb;
  $lineups = ll706_lineup_table_name();
  $photos = ll706_auth_photo_table_name();
  $logs = ll706_auth_work_logs_table_name();
  $units = ll706_lineup_units_table_name();
  $where = "l.status = 'published' AND p.deleted_at IS NULL AND w.deleted_at IS NULL";
  if ($require_user) {
    $user_id = filter_var($request->get_param('user_id'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    if ($user_id === false || $user_id === null) return new WP_Error('lineup_invalid_user', 'user_id is required.', ['status' => 400]);
    $where .= $wpdb->prepare(' AND l.user_id = %d', $user_id);
  }
  if ($request->get_param('work_date') !== null) {
    $date = (string) $request->get_param('work_date');
    if (!ll706_lineup_valid_date($date)) return new WP_Error('lineup_invalid_date', 'Invalid work_date.', ['status' => 400]);
    $where .= $wpdb->prepare(' AND l.work_date = %s', $date);
  }
  foreach (['date_from' => '>=', 'date_to' => '<='] as $parameter => $operator) {
    if ($request->get_param($parameter) === null) continue;
    $date = (string) $request->get_param($parameter);
    if (!ll706_lineup_valid_date($date)) return new WP_Error('lineup_invalid_date', 'Invalid ' . $parameter . '.', ['status' => 400]);
    $where .= $wpdb->prepare(" AND l.work_date {$operator} %s", $date);
  }
  if ($request->get_param('shift') !== null) {
    $shift = ll706_auth_normalize_work_log_shift($request->get_param('shift'));
    if ($shift === '') return new WP_Error('lineup_invalid_shift', 'Invalid shift.', ['status' => 400]);
    $where .= $wpdb->prepare(' AND l.shift = %s', $shift);
  }
  if ($request->get_param('unit') !== null) {
    $unit = strtoupper(preg_replace('/\s+/', '', (string) $request->get_param('unit')));
    if (!preg_match('/^[A-Z0-9-]{1,64}$/', $unit)) return new WP_Error('lineup_invalid_unit', 'Invalid unit.', ['status' => 400]);
    $where .= $wpdb->prepare(" AND EXISTS (SELECT 1 FROM {$units} u WHERE u.lineup_id = l.id AND u.unit_number = %s)", $unit);
  }
  $after = max(0, (int) $request->get_param('after_id'));
  $where .= $wpdb->prepare(' AND l.id > %d', $after);
  $limit = min(100, max(1, (int) ($request->get_param('limit') ?? 25)));
  $rows = $wpdb->get_results("SELECT l.* FROM {$lineups} l
    INNER JOIN {$photos} p ON p.id = l.photo_id
    INNER JOIN {$logs} w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid AND w.work_date = l.work_date AND w.shift = l.shift
    WHERE {$where} ORDER BY l.id ASC LIMIT {$limit}", ARRAY_A);
  if ($rows === null) return new WP_Error('lineup_query_failed', 'Unable to search lineups.', ['status' => 500]);
  $results = [];
  foreach ($rows as $row) {
    $unit_rows = ll706_lineup_units_for_id($row['id']);
    if ($unit_rows === null) return new WP_Error('lineup_query_failed', 'Unable to load lineup rows.', ['status' => 500]);
    $results[] = [
      'lineup_id' => (int) $row['id'],
      'lineup_key' => ll706_lineup_key($row['work_date'], $row['shift'], $row['fingerprint']),
      'photo_id' => (int) $row['photo_id'],
      'photo_url' => ll706_lineup_photo_url((int) $row['photo_id']),
      'uploaded_by_user_id' => (int) $row['user_id'],
      'work_date' => $row['work_date'],
      'shift' => $row['shift'],
      'date_inferred' => empty($row['printed_date']),
      'units' => $unit_rows,
    ];
  }
  $next = $rows ? (int) $rows[count($rows) - 1]['id'] : $after;
  $response = new WP_REST_Response(['ok' => true, 'lineups' => $results, 'next_after_id' => $next], 200);
  $response->header('Cache-Control', 'private, no-store');
  return $response;
}

function ll706_lineup_photo_url($photo_id) {
  return add_query_arg([
    'action' => 'll706_lineup_photo',
    'photo_id' => (int) $photo_id,
  ], admin_url('admin-post.php'));
}

function ll706_lineup_delete_matching($where) {
  global $wpdb;
  if (get_option('ll706_lineup_db_version', '') !== LL706_LINEUP_DB_VERSION) return;
  $lineups = ll706_lineup_table_name();
  $units = ll706_lineup_units_table_name();
  if ($wpdb->query("DELETE u FROM {$units} u INNER JOIN {$lineups} l ON l.id = u.lineup_id WHERE {$where}") === false) return;
  $wpdb->query("DELETE l FROM {$lineups} l WHERE {$where}");
}

function ll706_lineup_forget_photo($photo_id) {
  global $wpdb;
  ll706_lineup_delete_matching($wpdb->prepare('l.photo_id = %d', (int) $photo_id));
}

function ll706_lineup_forget_entry($user_id, $entry_uuid) {
  global $wpdb;
  ll706_lineup_delete_matching($wpdb->prepare('l.user_id = %d AND l.entry_uuid = %s', (int) $user_id, $entry_uuid));
}

function ll706_lineup_forget_user($user_id) {
  global $wpdb;
  ll706_lineup_delete_matching($wpdb->prepare('l.user_id = %d', (int) $user_id));
}

/** Repairs missed hooks, including photos purged after storage was unavailable. */
function ll706_lineup_purge_deleted_sources() {
  global $wpdb;
  if (get_option('ll706_lineup_db_version', '') !== LL706_LINEUP_DB_VERSION) return;
  $lineups = ll706_lineup_table_name();
  $units = ll706_lineup_units_table_name();
  $photos = ll706_auth_photo_table_name();
  $logs = ll706_auth_work_logs_table_name();
  $joins = "LEFT JOIN {$photos} p ON p.id = l.photo_id LEFT JOIN {$logs} w ON w.user_id = l.user_id AND w.entry_uuid = l.entry_uuid";
  $stale = 'p.id IS NULL OR p.deleted_at IS NOT NULL OR w.id IS NULL OR w.deleted_at IS NOT NULL';
  if ($wpdb->query("DELETE u FROM {$units} u INNER JOIN {$lineups} l ON l.id = u.lineup_id {$joins} WHERE {$stale}") === false) return;
  $wpdb->query("DELETE l FROM {$lineups} l {$joins} WHERE {$stale}");
  $wpdb->query("DELETE u FROM {$units} u LEFT JOIN {$lineups} l ON l.id = u.lineup_id WHERE l.id IS NULL");
}

function ll706_lineup_member_photo_login() {
  $photo_id = isset($_GET['photo_id']) ? (int) $_GET['photo_id'] : 0;
  wp_safe_redirect(wp_login_url(ll706_lineup_photo_url($photo_id)));
  exit;
}

/** Browser-cookie viewer; never accepts a chat-supplied user number as proof. */
function ll706_lineup_member_photo() {
  global $wpdb;
  $user_id = get_current_user_id();
  if (!$user_id || !ll706_auth_api_is_user_approved($user_id)) {
    wp_die('Access denied.', 'Lineup photo', ['response' => 403]);
  }
  $photo_id = isset($_GET['photo_id']) ? (int) $_GET['photo_id'] : 0;
  $photo = $photo_id > 0 ? ll706_lineup_active_photo($photo_id) : null;
  if (!$photo) wp_die('Lineup photo not found.', 'Lineup photo', ['response' => 404]);
  $lineups = ll706_lineup_table_name();
  $published = $wpdb->get_var($wpdb->prepare(
    "SELECT id FROM {$lineups} WHERE photo_id = %d AND status = 'published' AND work_date = %s AND shift = %s LIMIT 1",
    $photo_id, $photo['work_date'], $photo['shift']
  ));
  if (!$published) wp_die('Lineup photo not found.', 'Lineup photo', ['response' => 404]);
  $root = ll706_auth_photo_storage_root();
  if (is_wp_error($root)) wp_die('Lineup photo unavailable.', 'Lineup photo', ['response' => 503]);
  $path = ll706_auth_photo_path($root, $photo['photo_uuid']);
  if (is_link($path) || !is_file($path) || !is_readable($path)) {
    wp_die('Lineup photo unavailable.', 'Lineup photo', ['response' => 503]);
  }
  status_header(200);
  header('Content-Type: image/jpeg');
  header('Content-Disposition: inline; filename="lineup.jpg"');
  header('Content-Length: ' . filesize($path));
  header('Cache-Control: private, no-store, max-age=0');
  header('X-Content-Type-Options: nosniff');
  header('X-Frame-Options: DENY');
  readfile($path);
  exit;
}
