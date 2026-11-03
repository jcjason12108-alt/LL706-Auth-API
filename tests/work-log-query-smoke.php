<?php
// Run with: php tests/work-log-query-smoke.php.
define('ABSPATH', __DIR__ . '/');
function add_action() {}
class WP_Error {
  public $code;
  public function __construct($code) { $this->code = $code; }
}
class WP_REST_Request {
  private $headers;
  private $params;
  public function __construct($headers = [], $params = []) {
    $this->headers = $headers;
    $this->params = $params;
  }
  public function get_header($name) { return $this->headers[$name] ?? ''; }
  public function get_param($name) { return $this->params[$name] ?? null; }
}
class WP_REST_Response {
  public $data;
  public function __construct($data) { $this->data = $data; }
  public function header($name, $value) {}
}
$wpdb = new class {
  public $last_query = '';
  public $queries = [];
  public function prepare($format, ...$args) {
    if (count($args) === 1 && is_array($args[0])) $args = $args[0];
    return vsprintf($format, $args);
  }
  public function get_results($query, $format) {
    $this->last_query = $query;
    $this->queries[] = $query;
    if (strpos($query, 'FROM wp_ll706_work_logs WHERE user_id = 5') !== false) {
      return [['id' => 12, 'entry_uuid' => 'entry-5']];
    }
    if (strpos($query, 'FROM wp_ll706_work_log_photos p') !== false) {
      return [['id' => 8, 'entry_uuid' => 'entry-5', 'photo_uuid' => 'photo-5']];
    }
    return [];
  }
};
define('ARRAY_A', 'ARRAY_A');
function ll706_auth_work_logs_table_name() { return 'wp_ll706_work_logs'; }
function ll706_auth_photo_table_name() { return 'wp_ll706_work_log_photos'; }
function ll706_auth_format_work_log_row($row) { return $row; }
function ll706_auth_photo_format_row($row) { return ['photo_uuid' => $row['photo_uuid']]; }
require dirname(__DIR__) . '/work-log-query.php';
function check($condition, $message) {
  if (!$condition) throw new RuntimeException($message);
}

$request = new WP_REST_Request();
check(ll706_work_log_query_require_key($request)->code === 'work_log_query_unavailable', 'Unconfigured service was available');
define('LL706_WORK_LOG_QUERY_SERVICE_KEY', str_repeat('q', 40));
check(ll706_work_log_query_require_key($request)->code === 'work_log_query_forbidden', 'Missing key was accepted');
check(ll706_work_log_query_require_key(new WP_REST_Request(['x-ll706-work-log-query-key' => 'wrong']))->code === 'work_log_query_forbidden', 'Wrong key was accepted');
$authorized = new WP_REST_Request(['x-ll706-work-log-query-key' => str_repeat('q', 40)]);
check(ll706_work_log_query_require_key($authorized) === true, 'Correct key was rejected');
check(ll706_work_log_query_entries(new WP_REST_Request([], ['user_id' => 0]))->code === 'work_log_query_invalid_user', 'Invalid user was accepted');
foreach ([4, 5] as $user_id) {
  $result = ll706_work_log_query_entries(new WP_REST_Request([], ['user_id' => $user_id]));
  check($result instanceof WP_REST_Response && $result->data['user_id'] === $user_id, 'A valid user was rejected');
  check((bool) array_filter($wpdb->queries, static function ($query) use ($user_id) {
    return strpos($query, 'user_id = ' . $user_id . ' AND deleted_at IS NULL') !== false;
  }), 'Query did not isolate the requested user');
  if ($user_id === 5) {
    check($result->data['entries'][0]['photos'][0]['photo_uuid'] === 'photo-5', 'Photo metadata was not attached to its entry');
    check(strpos($wpdb->last_query, 'p.user_id = 5') !== false, 'Photo lookup did not isolate the requested user');
  }
}
check(ll706_work_log_query_valid_date('2028-02-29'), 'Valid leap date was rejected');
check(!ll706_work_log_query_valid_date('2027-02-29'), 'Invalid leap date was accepted');
check(ll706_work_log_query_entries(new WP_REST_Request([], ['user_id' => 5, 'has_photos' => 'maybe']))->code === 'work_log_query_invalid_photo_filter', 'Invalid photo filter was accepted');
$with_photos = ll706_work_log_query_entries(new WP_REST_Request([], ['user_id' => 5, 'has_photos' => '1']));
check($with_photos instanceof WP_REST_Response, 'Photo-only query was rejected');
check((bool) array_filter($wpdb->queries, static function ($query) {
  return strpos($query, 'EXISTS (SELECT 1 FROM wp_ll706_work_log_photos p') !== false
    && strpos($query, 'p.user_id = wp_ll706_work_logs.user_id') !== false
    && strpos($query, 'p.deleted_at IS NULL') !== false;
}), 'Photo-only query did not require an active photo owned by the entry');
echo "work-log query smoke checks passed\n";
