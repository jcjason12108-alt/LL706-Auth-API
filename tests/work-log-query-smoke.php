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
require dirname(__DIR__) . '/work-log-query.php';
function check($condition, $message) {
  if (!$condition) throw new RuntimeException($message);
}

$request = new WP_REST_Request();
check(ll706_work_log_query_require_key($request)->code === 'work_log_query_unavailable', 'Unconfigured service was available');
define('LL706_WORK_LOG_QUERY_SERVICE_KEY', str_repeat('q', 40));
define('LL706_WORK_LOG_QUERY_TEST_USER_ID', 4);
check(ll706_work_log_query_require_key($request)->code === 'work_log_query_forbidden', 'Missing key was accepted');
check(ll706_work_log_query_require_key(new WP_REST_Request(['x-ll706-work-log-query-key' => 'wrong']))->code === 'work_log_query_forbidden', 'Wrong key was accepted');
$authorized = new WP_REST_Request(['x-ll706-work-log-query-key' => str_repeat('q', 40)]);
check(ll706_work_log_query_require_key($authorized) === true, 'Correct key was rejected');
check(ll706_work_log_query_entries(new WP_REST_Request([], ['user_id' => 5]))->code === 'work_log_query_forbidden', 'Another user was accepted');
check(ll706_work_log_query_entries(new WP_REST_Request([], ['user_id' => 0]))->code === 'work_log_query_invalid_user', 'Invalid user was accepted');
check(ll706_work_log_query_valid_date('2028-02-29'), 'Valid leap date was rejected');
check(!ll706_work_log_query_valid_date('2027-02-29'), 'Invalid leap date was accepted');
echo "work-log query smoke checks passed\n";
