<?php
/**
 * Read-only, single-member Work Log query service for an isolated n8n test.
 * A chat-supplied user number is never treated as proof of member identity.
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
  $test_user = defined('LL706_WORK_LOG_QUERY_TEST_USER_ID') ? (int) LL706_WORK_LOG_QUERY_TEST_USER_ID : 0;
  if (strlen($key) < 32 || $test_user < 1) {
    return new WP_Error('work_log_query_unavailable', 'Work Log query test is not configured.', ['status' => 503]);
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
  if ((int) $user_id !== (int) LL706_WORK_LOG_QUERY_TEST_USER_ID) {
    return new WP_Error('work_log_query_forbidden', 'This test is limited to one member.', ['status' => 403]);
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

  $response = new WP_REST_Response([
    'ok' => true,
    'user_id' => (int) $user_id,
    'entries' => array_map('ll706_auth_format_work_log_row', $rows),
    'next_before_id' => $more ? $next : null,
    'more_records_possible' => $more,
    'keyword_is_substring_match' => $keyword !== '',
  ], 200);
  $response->header('Cache-Control', 'private, no-store');
  return $response;
}
