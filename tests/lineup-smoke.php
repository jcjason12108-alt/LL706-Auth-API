<?php
// Run with: php tests/lineup-smoke.php. WordPress is not required for pure helpers.
define('ABSPATH', __DIR__ . '/');
function add_action() {}
function get_option($key, $default = '') { return $key === 'll706_lineup_db_version' ? '1.0.0' : $default; }
function wp_unslash($value) { return stripslashes($value); }
function sanitize_textarea_field($value) { return trim(strip_tags($value)); }
function wp_json_encode($value) { return json_encode($value); }
function is_wp_error($value) { return $value instanceof WP_Error; }
class WP_Error {
  public $code;
  public function __construct($code) { $this->code = $code; }
}
class WP_REST_Request {
  private $key;
  public function __construct($key) { $this->key = $key; }
  public function get_header($name) { return $name === 'x-ll706-lineup-key' ? $this->key : ''; }
}
require dirname(__DIR__) . '/work-log-lineups.php';

function check($condition, $message) {
  if (!$condition) throw new RuntimeException($message);
}

check(ll706_lineup_valid_date('2028-02-29'), 'Leap day rejected');
check(!ll706_lineup_valid_date('2027-02-29'), 'Invalid date accepted');
$rows = ll706_lineup_normalized_units([
  ['unit_number' => ' 5433 ', 'cover_figure' => '1/F', 'work_to_do' => '  Air leak ', 'assigned_names' => ['Alex']],
  ['unit_number' => '9790', 'work_to_do' => 'Inspection', 'assigned_names' => []],
]);
check(!is_wp_error($rows) && $rows[0]['unit_number'] === '5433', 'Unit normalization failed');
$reversed = array_reverse($rows);
check(ll706_lineup_fingerprint($rows) === ll706_lineup_fingerprint($reversed), 'Photo row order changed fingerprint');
$name_order = $rows;
$name_order[0]['assigned_names'] = ['Alex', 'Morgan'];
$swapped_names = $name_order;
$swapped_names[0]['assigned_names'] = ['Morgan', 'Alex'];
check(ll706_lineup_fingerprint($name_order) === ll706_lineup_fingerprint($swapped_names), 'Name order changed fingerprint');
$changed = $rows;
$changed[0]['work_to_do'] = 'Oil leak';
check(ll706_lineup_fingerprint($rows) !== ll706_lineup_fingerprint($changed), 'Revised task merged with original');
check(ll706_lineup_key('2026-10-22', '1st', ll706_lineup_fingerprint($rows)) !== ll706_lineup_key('2026-10-22', '2nd', ll706_lineup_fingerprint($rows)), 'Different shifts merged');
check(is_wp_error(ll706_lineup_normalized_units([['unit_number' => '../5433']])), 'Invalid unit accepted');

$unconfigured = ll706_lineup_require_service_key(new WP_REST_Request(''));
check(is_wp_error($unconfigured) && $unconfigured->code === 'lineup_service_unavailable', 'Unconfigured service accepted request');
define('LL706_LINEUP_SERVICE_KEY', str_repeat('s', 40));
$forbidden = ll706_lineup_require_service_key(new WP_REST_Request('wrong'));
check(is_wp_error($forbidden) && $forbidden->code === 'lineup_service_forbidden', 'Wrong key accepted');
check(ll706_lineup_require_service_key(new WP_REST_Request(str_repeat('s', 40))) === true, 'Correct service key rejected');
echo "lineup smoke checks passed\n";
