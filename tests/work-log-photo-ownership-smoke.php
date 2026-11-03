<?php
// Run with: php tests/work-log-photo-ownership-smoke.php.
define('ABSPATH', __DIR__ . '/');
function add_action() {}
function add_filter() {}
function ll706_auth_work_logs_table_name() { return 'wp_ll706_work_logs'; }
$wpdb = new class {
  public $last_query;
  public function prepare($format, ...$args) { return vsprintf($format, $args); }
  public function get_var($query) {
    $this->last_query = $query;
    if (strpos($query, 'user_id = 4') === false) return false;
    if (strpos($query, 'LOWER(entry_uuid) = 41e48dfb-0c9a-4a2a-b855-cc66f332364c') === false) return false;
    return 12; // Stored Work Log UUID has uppercase letters; the photo reference is lowercase.
  }
};
require dirname(__DIR__) . '/work-log-photos.php';
if (!ll706_auth_photo_owned_entry(4, '41E48DFB-0C9A-4A2A-B855-CC66F332364C')) {
  throw new RuntimeException('Mixed-case Work Log photo owner was not found');
}
if (ll706_auth_photo_owned_entry(5, '41e48dfb-0c9a-4a2a-b855-cc66f332364c')) {
  throw new RuntimeException('Another user could access the photo entry');
}
echo "work-log photo ownership smoke checks passed\n";
