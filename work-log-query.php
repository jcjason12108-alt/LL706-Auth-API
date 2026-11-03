<?php
/**
 * Read-only Work Log query service for the n8n chat workflow.
 * The service key authorizes n8n; the requested user_id selects the member's entries.
 */

if (!defined('ABSPATH')) exit;

add_action('rest_api_init', 'll706_work_log_query_register_route');

function ll706_work_log_query_register_route() {
  register_rest_route('ll706/v1', '/work-log-query/entries', [
    'methods' => 'GET',
    'callback' => 'll706_work_log_query_entries',
    'permission_callback' => 'll706_work_log_query_require_key',
  ]);
}

function ll706_work_log_query_require_key(WP_REST_Request $request) {
  $key = defined('LL706_WORK_LOG_QUERY_SERVICE_KEY') ? (string) LL706_WORK_LOG_QUERY_SERVICE_KEY : '';
  if (strlen($key) < 32) {
    return new WP_Error('work_log_query_unavailable', 'Work Log query service is not configured.', ['status' => 503]);
  }
  $provided = (string) $request->get_header('x-ll706-work-log-query-key');
  if ($provided === '' || !hash_equals($key, $provided)) {
    return new WP_Error('work_log_query_forbidden', 'Access denied.', ['status' => 403]);
  }
  return true;
}

function ll706_work_log_query_valid_date($value) {
  if (!is_string($value) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) return false;
  $date = DateTime::createFromFormat('!Y-m-d', $value);
  return $date && $date->format('Y-m-d') === $value;
}

function ll706_work_log_query_entries(WP_REST_Request $request) {
  global $wpdb;

  $user_id = filter_var($request->get_param('user_id'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
  if ($user_id === false || $user_id === null) {
    return new WP_Error('work_log_query_invalid_user', 'A valid user_id is required.', ['status' => 400]);
  }
  $table = ll706_auth_work_logs_table_name();
  $where = $wpdb->prepare('user_id = %d AND deleted_at IS NULL', (int) $user_id);
  foreach (['work_date' => '=', 'date_from' => '>=', 'date_to' => '<='] as $name => $operator) {
    $date = $request->get_param($name);
    if ($date === null || $date === '') continue;
    if (!ll706_work_log_query_valid_date($date)) {
      return new WP_Error('work_log_query_invalid_date', 'Invalid ' . $name . '.', ['status' => 400]);
    }
    $where .= $wpdb->prepare(" AND work_date {$operator} %s", $date);
  }
  $shift = $request->get_param('shift');
  if ($shift !== null && $shift !== '') {
    $shift = is_string($shift) ? ll706_auth_normalize_work_log_shift($shift) : '';
    if (!in_array($shift, ['1st', '2nd', '3rd'], true)) {
      return new WP_Error('work_log_query_invalid_shift', 'Invalid shift.', ['status' => 400]);
    }
    $where .= $wpdb->prepare(' AND shift = %s', $shift);
  }

  $keyword = $request->get_param('keyword');
  if ($keyword !== null && !is_string($keyword)) {
    return new WP_Error('work_log_query_invalid_keyword', 'Invalid keyword.', ['status' => 400]);
  }
  $keyword = trim($keyword ?? '');
  if (strlen($keyword) > 100) {
    return new WP_Error('work_log_query_invalid_keyword', 'keyword is too long.', ['status' => 400]);
  }
  if ($keyword !== '') {
    $like = '%' . $wpdb->esc_like($keyword) . '%';
    $where .= $wpdb->prepare(
      ' AND (work_items LIKE %s OR notes LIKE %s OR supervisor LIKE %s OR worked_with LIKE %s)',
      $like, $like, $like, $like
    );
  }

  $has_photos = $request->get_param('has_photos');
  if ($has_photos !== null && $has_photos !== '') {
    $has_photos = filter_var($has_photos, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    if ($has_photos === null) {
      return new WP_Error('work_log_query_invalid_photo_filter', 'Invalid has_photos.', ['status' => 400]);
    }
    if ($has_photos) {
      $photos_table = ll706_auth_photo_table_name();
      $where .= " AND EXISTS (SELECT 1 FROM {$photos_table} p WHERE p.user_id = {$table}.user_id AND p.entry_uuid = {$table}.entry_uuid AND p.deleted_at IS NULL)";
    }
  }

  $before = $request->get_param('before_id');
  if ($before !== null && $before !== '') {
    $before = filter_var($before, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
    if ($before === false) return new WP_Error('work_log_query_invalid_cursor', 'Invalid before_id.', ['status' => 400]);
    $where .= $wpdb->prepare(' AND id < %d', $before);
  }
  $limit = $request->get_param('limit');
  $limit = $limit === null ? 50 : filter_var($limit, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 100]]);
  if ($limit === false) return new WP_Error('work_log_query_invalid_limit', 'limit must be from 1 to 100.', ['status' => 400]);

  $rows = $wpdb->get_results(
    "SELECT * FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT " . ((int) $limit + 1),
    ARRAY_A
  );
  if ($rows === null) return new WP_Error('work_log_query_failed', 'Unable to read Work Logs.', ['status' => 500]);
  $more = count($rows) > $limit;
  $rows = array_slice($rows, 0, $limit);
  $next = $rows ? (int) $rows[count($rows) - 1]['id'] : null;

  $photos_by_entry = [];
  if ($rows) {
    $entry_uuids = array_values(array_unique(array_column($rows, 'entry_uuid')));
    $placeholders = implode(', ', array_fill(0, count($entry_uuids), '%s'));
    $photos_table = ll706_auth_photo_table_name();
    $photo_rows = $wpdb->get_results($wpdb->prepare(
      "SELECT p.* FROM {$photos_table} p INNER JOIN {$table} w ON w.user_id = p.user_id AND w.entry_uuid = p.entry_uuid WHERE p.user_id = %d AND p.entry_uuid IN ({$placeholders}) AND p.deleted_at IS NULL AND w.deleted_at IS NULL ORDER BY p.created_at, p.id",
      array_merge([(int) $user_id], $entry_uuids)
    ), ARRAY_A);
    if ($photo_rows === null) return new WP_Error('work_log_query_failed', 'Unable to read Work Log photos.', ['status' => 500]);
    foreach ($photo_rows as $photo_row) {
      $photo = ll706_auth_photo_format_row($photo_row);
      $photos_by_entry[strtolower((string) $photo_row['entry_uuid'])][] = $photo;
    }
  }

  $entries = array_map(static function ($row) use ($photos_by_entry) {
    $entry = ll706_auth_format_work_log_row($row);
    $entry['photos'] = $photos_by_entry[strtolower((string) $row['entry_uuid'])] ?? [];
    return $entry;
  }, $rows);

  $response = new WP_REST_Response([
    'ok' => true,
    'user_id' => (int) $user_id,
    'entries' => $entries,
    'next_before_id' => $more ? $next : null,
    'more_records_possible' => $more,
    'keyword_is_substring_match' => $keyword !== '',
  ], 200);
  $response->header('Cache-Control', 'private, no-store');
  return $response;
}
