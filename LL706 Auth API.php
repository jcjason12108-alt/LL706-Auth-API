<?php
/**
 * Plugin Name: LL706 Auth API
 * Plugin URI: https://github.com/jcjason12108-alt/LL706-Auth-API/
 * Description: WordPress login + manual approval + JWT auth for LL706 mobile/web apps.
 * Version: 0.9.2
 * Requires at least: 6.0
 * Tested up to: 7.0
 * Requires PHP: 7.4
 * Author: Jason Cox
 * Author URI: https://github.com/jcjason12108-alt
 * License: GPL-2.0-or-later
 * Text Domain: ll706-auth-api
 */

if (!defined('ABSPATH')) exit;

require_once __DIR__ . '/plugin-update-checker/plugin-update-checker.php';

$ll706_auth_api_update_checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker(
  'https://github.com/jcjason12108-alt/LL706-Auth-API/',
  __FILE__,
  'll706-auth-api'
);
$ll706_auth_api_update_checker->setBranch('main');

$ll706_auth_api_github_token = ll706_auth_api_get_github_update_token();

if (!empty($ll706_auth_api_github_token)) {
  $ll706_auth_api_update_checker->setAuthentication($ll706_auth_api_github_token);
}

add_filter(
  $ll706_auth_api_update_checker->getUniqueName('vcs_update_detection_strategies'),
  static function (array $strategies): array {
    return isset($strategies['branch']) ? ['branch' => $strategies['branch']] : $strategies;
  }
);

if (!defined('LL706_WORK_LOG_DB_VERSION')) {
  define('LL706_WORK_LOG_DB_VERSION', '1.0.0');
}

function ll706_auth_api_get_github_update_token() {
  if (defined('LL706_AUTH_API_GITHUB_TOKEN') && LL706_AUTH_API_GITHUB_TOKEN !== '') {
    return LL706_AUTH_API_GITHUB_TOKEN;
  }

  $env_token = getenv('LL706_AUTH_API_GITHUB_TOKEN');
  return is_string($env_token) ? trim($env_token) : '';
}

register_activation_hook(__FILE__, 'll706_auth_api_activate');
register_deactivation_hook(__FILE__, 'll706_auth_api_deactivate');

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

  register_setting('ll706_auth_api', 'll706_dashboard_form_config', [
    'type' => 'array',
    'sanitize_callback' => 'll706_auth_api_sanitize_dashboard_form_config',
    'default' => ll706_auth_api_dashboard_form_defaults(),
  ]);
});

add_filter('option_page_capability_ll706_auth_api', function () {
  return 'manage_options';
});

add_action('show_user_profile', 'll706_auth_api_render_user_access_controls');
add_action('edit_user_profile', 'll706_auth_api_render_user_access_controls');
add_action('personal_options_update', 'll706_auth_api_save_user_access_controls');
add_action('edit_user_profile_update', 'll706_auth_api_save_user_access_controls');
add_filter('manage_users_columns', 'll706_auth_api_add_users_column');
add_filter('manage_users_custom_column', 'll706_auth_api_render_users_column', 10, 3);
add_action('admin_post_ll706_toggle_access', 'll706_auth_api_handle_toggle_access');
add_action('admin_post_ll706_clear_login_log', 'll706_auth_api_handle_clear_login_log');
add_action('admin_post_ll706_export_login_summary', 'll706_auth_api_handle_export_login_summary');
add_action('admin_notices', 'll706_auth_api_access_notice');
add_action('admin_notices', 'll706_auth_api_log_notice');
add_action('plugins_loaded', 'll706_auth_api_maybe_create_log_table');
add_action('plugins_loaded', 'll706_auth_maybe_upgrade_work_log_db');
add_action('plugins_loaded', 'll706_auth_api_ensure_cleanup_schedule');
add_action('plugins_loaded', 'll706_auth_api_start_wordfence_login_buffer', 0);
add_action('ll706_auth_api_daily_cleanup', 'll706_auth_api_run_log_cleanup');
ll706_auth_api_start_wordfence_login_buffer();

function ll706_auth_api_defaults() {
  return [
    'jwt_secret'        => '',
    'local_value'       => '706',
    'approved_meta_key' => 'll706_approved',
    'token_ttl_admin'   => 12 * HOUR_IN_SECONDS,
    'token_ttl_exec'    => 12 * HOUR_IN_SECONDS,
    'token_ttl_member'  => 24 * HOUR_IN_SECONDS,
    'token_version'     => 1,
    'login_log_retention_days' => 90,
  ];
}

function ll706_auth_api_get_options() {
  $saved = get_option('ll706_auth_api_options', []);
  return array_merge(ll706_auth_api_defaults(), is_array($saved) ? $saved : []);
}

function ll706_auth_api_dashboard_form_defaults() {
  return [
    'enabled'      => false,
    'title'        => '',
    'subtitle'     => '',
    'button_title' => 'Open Form',
    'url'          => '',
    'audience'     => ['all'],
    'updated_at'   => '',
  ];
}

function ll706_auth_api_dashboard_form_audience_choices() {
  return [
    'all'              => 'All Members',
    'admin'            => 'Admin',
    'executive_board'  => 'Executive Board',
    'general_chairman' => 'General Chairman',
  ];
}

function ll706_auth_api_dashboard_form_allowed_audience_values() {
  return [
    'all',
    'all_members',
    'admin',
    'administrator',
    'executive_board',
    'executive',
    'eboard',
    'e_board',
    'general_chairman',
    'general_chair',
    'chairman',
  ];
}

function ll706_auth_api_sanitize_dashboard_form_audience($audience, $unslash = true) {
  if ($audience === null || $audience === '') {
    return [];
  }

  if (!is_array($audience)) {
    $audience = [$audience];
  }

  $allowed = ll706_auth_api_dashboard_form_allowed_audience_values();
  $out = [];

  foreach ($audience as $value) {
    if (is_array($value) || is_object($value)) {
      continue;
    }

    $text = $unslash ? wp_unslash((string) $value) : (string) $value;
    $normalized = sanitize_key($text);
    if (in_array($normalized, $allowed, true)) {
      $out[] = $normalized;
    }
  }

  return array_values(array_unique($out));
}

function ll706_auth_api_normalize_dashboard_form_config($config, $touch_updated_at = false, $default_audience_when_missing = true, $unslash = false) {
  $defaults = ll706_auth_api_dashboard_form_defaults();
  $out = $defaults;

  if (!is_array($config)) {
    return $out;
  }

  if ($unslash) {
    $config = wp_unslash($config);
  }

  $out['enabled'] = ll706_auth_normalize_bool($config['enabled'] ?? false);
  $out['title'] = sanitize_text_field((string) ($config['title'] ?? ''));
  $out['subtitle'] = sanitize_textarea_field((string) ($config['subtitle'] ?? ''));

  $button_title = sanitize_text_field((string) ($config['button_title'] ?? $defaults['button_title']));
  $out['button_title'] = $button_title !== '' ? $button_title : $defaults['button_title'];

  $out['url'] = esc_url_raw((string) ($config['url'] ?? ''));
  $out['audience'] = array_key_exists('audience', $config)
    ? ll706_auth_api_sanitize_dashboard_form_audience($config['audience'], false)
    : ($default_audience_when_missing ? $defaults['audience'] : []);

  $out['updated_at'] = sanitize_text_field((string) ($config['updated_at'] ?? ''));
  if ($touch_updated_at) {
    $out['updated_at'] = gmdate('Y-m-d\TH:i:s\Z');
  }

  return $out;
}

function ll706_auth_api_sanitize_dashboard_form_config($config) {
  return ll706_auth_api_normalize_dashboard_form_config($config, true, false, true);
}

function ll706_auth_api_get_dashboard_form_config() {
  $saved = get_option('ll706_dashboard_form_config', []);
  return ll706_auth_api_normalize_dashboard_form_config($saved, false, true, false);
}

function ll706_auth_api_is_valid_dashboard_form_url($url) {
  $url = esc_url_raw((string) $url);
  if ($url === '') {
    return false;
  }

  $parts = wp_parse_url($url);
  if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
    return false;
  }

  $scheme = strtolower((string) $parts['scheme']);
  if (!in_array($scheme, ['http', 'https'], true)) {
    return false;
  }

  return (bool) filter_var($url, FILTER_VALIDATE_URL);
}

function ll706_auth_api_dashboard_form_disabled_response() {
  return new WP_REST_Response(['enabled' => false], 200);
}

function ll706_auth_api_dashboard_form_response() {
  $config = ll706_auth_api_get_dashboard_form_config();

  if (empty($config['enabled']) || trim((string) $config['title']) === '' || !ll706_auth_api_is_valid_dashboard_form_url($config['url'])) {
    return ll706_auth_api_dashboard_form_disabled_response();
  }

  return new WP_REST_Response([
    'enabled'      => true,
    'title'        => $config['title'],
    'subtitle'     => $config['subtitle'],
    'button_title' => $config['button_title'],
    'url'          => $config['url'],
    'audience'     => array_values($config['audience']),
    'updated_at'   => $config['updated_at'] !== '' ? $config['updated_at'] : gmdate('Y-m-d\TH:i:s\Z'),
  ], 200);
}

function ll706_auth_api_admin_page_url($tab = 'history', $args = []) {
  $params = array_merge([
    'page' => 'll706-auth-api',
    'tab'  => $tab,
  ], $args);

  return add_query_arg($params, admin_url('options-general.php'));
}

function ll706_auth_api_get_current_tab() {
  $tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'history';

  if (!in_array($tab, ['overview', 'settings', 'history'], true)) {
    return 'history';
  }

  return $tab;
}

function ll706_auth_api_activate() {
  ll706_auth_api_maybe_create_log_table();
  ll706_auth_setup_work_logs_table();
  ll706_auth_api_ensure_cleanup_schedule();
  ll706_auth_api_run_log_cleanup();
}

function ll706_auth_api_deactivate() {
  ll706_auth_api_clear_cleanup_schedule();
}

function ll706_auth_api_log_table_name() {
  global $wpdb;
  return $wpdb->prefix . 'll706_auth_login_log';
}

function ll706_auth_work_logs_table_name() {
  global $wpdb;
  return $wpdb->prefix . 'll706_work_logs';
}

function ll706_auth_api_get_table_count($table_name, $where_sql = '1=1') {
  global $wpdb;

  return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table_name} WHERE {$where_sql}");
}

function ll706_auth_maybe_upgrade_work_log_db() {
  $current = get_option('ll706_work_log_db_version', '');

  if ($current !== LL706_WORK_LOG_DB_VERSION) {
    ll706_auth_setup_work_logs_table();
  }
}

function ll706_auth_setup_work_logs_table() {
  global $wpdb;

  require_once ABSPATH . 'wp-admin/includes/upgrade.php';

  $table_name = ll706_auth_work_logs_table_name();
  $charset_collate = $wpdb->get_charset_collate();
  $sql = "CREATE TABLE {$table_name} (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    user_id bigint(20) unsigned NOT NULL,
    entry_uuid char(36) NOT NULL,
    work_date date NOT NULL,
    shift varchar(20) NOT NULL,
    doubled tinyint(1) NOT NULL DEFAULT 0,
    supervisor text NULL,
    worked_with longtext NULL,
    notes longtext NULL,
    work_items longtext NOT NULL,
    created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at datetime NULL DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY user_entry_uuid (user_id, entry_uuid),
    KEY user_deleted_work_date (user_id, deleted_at, work_date)
  ) {$charset_collate};";

  dbDelta($sql);
  update_option('ll706_work_log_db_version', LL706_WORK_LOG_DB_VERSION, false);
}

function ll706_auth_api_maybe_create_log_table() {
  global $wpdb;

  $table_name = ll706_auth_api_log_table_name();
  $table_exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table_name));

  if ($table_exists === $table_name && get_option('ll706_auth_api_db_version') === '2') {
    return;
  }

  require_once ABSPATH . 'wp-admin/includes/upgrade.php';

  $charset_collate = $wpdb->get_charset_collate();
  $sql = "CREATE TABLE {$table_name} (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    user_id bigint(20) unsigned NOT NULL,
    username varchar(60) NOT NULL DEFAULT '',
    email varchar(100) NOT NULL DEFAULT '',
    role varchar(100) NOT NULL DEFAULT '',
    ip_address varchar(100) NOT NULL DEFAULT '',
    user_agent text NULL,
    logged_in_at datetime NOT NULL,
    expires_at datetime NULL,
    token_version bigint(20) unsigned NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    KEY user_id (user_id),
    KEY logged_in_at (logged_in_at),
    KEY expires_at (expires_at)
  ) {$charset_collate};";

  dbDelta($sql);
  update_option('ll706_auth_api_db_version', '2', false);
}

function ll706_auth_api_get_client_ip() {
  $candidates = [
    'HTTP_CF_CONNECTING_IP',
    'HTTP_X_FORWARDED_FOR',
    'HTTP_X_REAL_IP',
    'HTTP_CLIENT_IP',
    'REMOTE_ADDR',
  ];

  foreach ($candidates as $key) {
    if (empty($_SERVER[$key])) {
      continue;
    }

    $value = sanitize_text_field(wp_unslash($_SERVER[$key]));

    if ($key === 'HTTP_X_FORWARDED_FOR') {
      $parts = array_map('trim', explode(',', $value));
      $value = $parts[0] ?? '';
    }

    if ($value !== '') {
      return substr($value, 0, 100);
    }
  }

  return '';
}

function ll706_auth_api_record_login(WP_User $user, $role, $expires_at, $token_version) {
  global $wpdb;

  ll706_auth_api_maybe_create_log_table();

  $expires_at_gmt = gmdate('Y-m-d H:i:s', (int) $expires_at);

  $wpdb->insert(
    ll706_auth_api_log_table_name(),
    [
      'user_id'      => $user->ID,
      'username'     => $user->user_login,
      'email'        => $user->user_email,
      'role'         => (string) $role,
      'ip_address'   => ll706_auth_api_get_client_ip(),
      'user_agent'   => isset($_SERVER['HTTP_USER_AGENT']) ? substr(sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])), 0, 65535) : '',
      'logged_in_at' => current_time('mysql', true),
      'expires_at'   => $expires_at_gmt,
      'token_version'=> (int) $token_version,
    ],
    ['%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d']
  );
}

function ll706_auth_api_get_latest_login_summary($limit = 50) {
  global $wpdb;

  ll706_auth_api_maybe_create_log_table();

  $table_name = ll706_auth_api_log_table_name();
  $limit_sql = '';

  if ((int) $limit > 0) {
    $limit = max(1, min(5000, (int) $limit));
    $limit_sql = $wpdb->prepare(' LIMIT %d', $limit);
  }

  return $wpdb->get_results(
      "SELECT l.id, l.user_id, l.username, l.email, l.role, l.ip_address, l.user_agent, l.logged_in_at, l.expires_at, l.token_version
       FROM {$table_name} l
       INNER JOIN (
         SELECT user_id, MAX(id) AS max_id
         FROM {$table_name}
         GROUP BY user_id
       ) latest ON latest.max_id = l.id
       ORDER BY l.logged_in_at DESC, l.id DESC" . $limit_sql,
    ARRAY_A
  );
}

function ll706_auth_api_get_login_status_label($entry) {
  $opts = ll706_auth_api_get_options();
  $expires_at = empty($entry['expires_at']) ? 0 : strtotime($entry['expires_at'] . ' UTC');

  if ((int) ($entry['token_version'] ?? 0) !== (int) $opts['token_version']) {
    return 'Invalidated';
  }

  if ($expires_at && $expires_at > time()) {
    return 'Active';
  }

  return 'Expired';
}

function ll706_auth_api_clear_login_logs() {
  global $wpdb;

  ll706_auth_api_maybe_create_log_table();
  $wpdb->query('DELETE FROM ' . ll706_auth_api_log_table_name());
}

function ll706_auth_api_ensure_cleanup_schedule() {
  if (!wp_next_scheduled('ll706_auth_api_daily_cleanup')) {
    wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'll706_auth_api_daily_cleanup');
  }
}

function ll706_auth_api_clear_cleanup_schedule() {
  $timestamp = wp_next_scheduled('ll706_auth_api_daily_cleanup');

  while ($timestamp) {
    wp_unschedule_event($timestamp, 'll706_auth_api_daily_cleanup');
    $timestamp = wp_next_scheduled('ll706_auth_api_daily_cleanup');
  }
}

function ll706_auth_api_run_log_cleanup() {
  global $wpdb;

  ll706_auth_api_maybe_create_log_table();

  $opts = ll706_auth_api_get_options();
  $days = max(0, (int) ($opts['login_log_retention_days'] ?? 0));

  if ($days < 1) {
    return;
  }

  $cutoff = gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS));
  $table_name = ll706_auth_api_log_table_name();

  $wpdb->query(
    $wpdb->prepare(
      "DELETE FROM {$table_name} WHERE logged_in_at < %s",
      $cutoff
    )
  );
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

function ll706_auth_api_log_notice() {
  if (!current_user_can('manage_options')) return;
  if (!isset($_GET['ll706_log_cleared'])) return;

  $screen = function_exists('get_current_screen') ? get_current_screen() : null;
  if ($screen && $screen->id !== 'settings_page_ll706-auth-api') return;

  echo '<div class="notice notice-success is-dismissible"><p>';
  echo esc_html('LL706 login log cleared.');
  echo '</p></div>';
}

function ll706_auth_api_handle_clear_login_log() {
  if (!current_user_can('manage_options')) {
    wp_die('You do not have permission to perform this action.');
  }

  check_admin_referer('ll706_clear_login_log');
  ll706_auth_api_clear_login_logs();

  wp_safe_redirect(add_query_arg('ll706_log_cleared', '1', ll706_auth_api_admin_page_url('history')));
  exit;
}

function ll706_auth_api_handle_export_login_summary() {
  if (!current_user_can('manage_options')) {
    wp_die('You do not have permission to perform this action.');
  }

  check_admin_referer('ll706_export_login_summary');

  $rows = ll706_auth_api_get_latest_login_summary(0);
  $filename = 'll706-auth-api-last-login-' . gmdate('Y-m-d-His') . '.csv';

  nocache_headers();
  header('Content-Type: text/csv; charset=utf-8');
  header('Content-Disposition: attachment; filename=' . $filename);

  $stream = fopen('php://output', 'w');
  if ($stream === false) {
    wp_die('Unable to export login summary.');
  }

  fputcsv($stream, ['user_id', 'username', 'email', 'role', 'last_login_gmt', 'status', 'ip_address', 'user_agent']);

  foreach ($rows as $entry) {
    fputcsv($stream, [
      $entry['user_id'],
      $entry['username'],
      $entry['email'],
      $entry['role'],
      $entry['logged_in_at'],
      ll706_auth_api_get_login_status_label($entry),
      $entry['ip_address'],
      $entry['user_agent'],
    ]);
  }

  fclose($stream);
  exit;
}

function ll706_auth_api_sanitize_options($opts) {
  $defaults = ll706_auth_api_defaults();
  $out = $defaults;

  if (!is_array($opts)) return $defaults;

  $opts = wp_unslash($opts);

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
  $out['login_log_retention_days'] = max(0, min(3650, intval($opts['login_log_retention_days'] ?? $defaults['login_log_retention_days'])));

  return $out;
}

function ll706_auth_api_settings_page() {
  if (!current_user_can('manage_options')) return;

  $tab = ll706_auth_api_get_current_tab();
  $opts = ll706_auth_api_get_options();
  $login_summaries = ll706_auth_api_get_latest_login_summary(50);

  if (isset($_POST['ll706_force_logout']) && check_admin_referer('ll706_force_logout')) {
    $opts['token_version']++;
    update_option('ll706_auth_api_options', $opts);
    echo '<div class="updated"><p><strong>All tokens invalidated.</strong></p></div>';
  }
?>
<div class="wrap">
<h1>LL706 Auth API</h1>

<p>This plugin provides secure login for the LL706 mobile app and API clients.</p>

<nav class="nav-tab-wrapper" style="margin-bottom: 20px;">
  <a href="<?php echo esc_url(ll706_auth_api_admin_page_url('history')); ?>" class="nav-tab <?php echo $tab === 'history' ? 'nav-tab-active' : ''; ?>">Login History</a>
  <a href="<?php echo esc_url(ll706_auth_api_admin_page_url('overview')); ?>" class="nav-tab <?php echo $tab === 'overview' ? 'nav-tab-active' : ''; ?>">Overview</a>
  <a href="<?php echo esc_url(ll706_auth_api_admin_page_url('settings')); ?>" class="nav-tab <?php echo $tab === 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
</nav>

<?php
switch ($tab) {
  case 'settings':
    ll706_auth_api_render_settings_tab($opts);
    break;
  case 'history':
    ll706_auth_api_render_history_tab($login_summaries);
    break;
  case 'overview':
  default:
    ll706_auth_api_render_overview_tab($opts);
    break;
}
?>
</div>
<?php
}

function ll706_auth_api_render_overview_tab($opts) {
?>
<h2>How This Plugin Works</h2>
<p>The app logs in through the REST API endpoint <code>/wp-json/ll706/v1/login</code>. Users can log in with either their username or email address, and a successful login returns a signed JWT token for the app to use on later requests.</p>

<table class="widefat striped" style="max-width: 1100px;">
  <tbody>
    <tr>
      <th style="width: 220px;">Approval Flow</th>
      <td>Members can register through <code>/wp-json/ll706/v1/register</code>. New registrations are marked pending, and app login is denied until the configured approval meta key is approved. Administrators are always allowed.</td>
    </tr>
    <tr>
      <th>Token Flow</th>
      <td>After a successful login, the plugin issues a JWT with a role-based expiration. The app uses that token when calling <code>/wp-json/ll706/v1/me</code>. Using <strong>Invalidate All Tokens</strong> increases the token version and forces every existing token to become invalid.</td>
    </tr>
    <tr>
      <th>Ultimate Member</th>
      <td>Registration writes profile values into Ultimate Member-compatible user meta. When Ultimate Member approves a user, this plugin automatically marks that account approved for app login too.</td>
    </tr>
    <tr>
      <th>Login Tracking</th>
      <td>Each successful app login records the user, role, IP address, user agent, token expiry, and login time. The <strong>Login History</strong> tab shows one row per user using the most recent successful app login.</td>
    </tr>
    <tr>
      <th>Retention</th>
      <td>Login rows are cleaned up daily by WordPress cron based on the retention period set in the <strong>Settings</strong> tab. Setting retention to <code>0</code> disables automatic cleanup.</td>
    </tr>
  </tbody>
</table>

<h2 style="margin-top: 24px;">Quick Reference</h2>
<table class="widefat striped" style="max-width: 1100px;">
  <thead>
    <tr>
      <th>Area</th>
      <th>What It Does</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>/login</code></td>
      <td>Authenticates the member and returns the JWT plus hydrated user data.</td>
    </tr>
    <tr>
      <td><code>/register</code></td>
      <td>Creates a new pending member and stores profile fields for review.</td>
    </tr>
    <tr>
      <td><code>/me</code></td>
      <td>Validates the bearer token and returns the latest app user payload.</td>
    </tr>
    <tr>
      <td>Users screen</td>
      <td>Lets administrators approve, block, or return a user to the legacy auto state.</td>
    </tr>
    <tr>
      <td>Current configuration</td>
      <td>Approval key: <code><?php echo esc_html($opts['approved_meta_key']); ?></code>, Local ID: <code><?php echo esc_html($opts['local_value']); ?></code>, Retention: <code><?php echo esc_html($opts['login_log_retention_days']); ?></code> days.</td>
    </tr>
  </tbody>
</table>
<?php
}

function ll706_auth_api_render_settings_tab($opts) {
  $dashboard_form = ll706_auth_api_get_dashboard_form_config();
  $dashboard_form_audiences = is_array($dashboard_form['audience']) ? $dashboard_form['audience'] : [];
?>
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

<h2>Dashboard Form Card</h2>
<table class="form-table">

<tr>
<th>Enabled</th>
<td>
<label>
<input type="checkbox" name="ll706_dashboard_form_config[enabled]" value="1" <?php checked(!empty($dashboard_form['enabled'])); ?> />
Show the dashboard form card in the app.
</label>
</td>
</tr>

<tr>
<th>Title</th>
<td>
<input type="text" name="ll706_dashboard_form_config[title]" value="<?php echo esc_attr($dashboard_form['title']); ?>" class="regular-text" />
<p class="description">Required when the form card is enabled.</p>
</td>
</tr>

<tr>
<th>Subtitle</th>
<td>
<textarea name="ll706_dashboard_form_config[subtitle]" rows="3" class="large-text"><?php echo esc_textarea($dashboard_form['subtitle']); ?></textarea>
</td>
</tr>

<tr>
<th>Button Title</th>
<td>
<input type="text" name="ll706_dashboard_form_config[button_title]" value="<?php echo esc_attr($dashboard_form['button_title']); ?>" class="regular-text" />
</td>
</tr>

<tr>
<th>URL</th>
<td>
<input type="url" name="ll706_dashboard_form_config[url]" value="<?php echo esc_attr($dashboard_form['url']); ?>" class="regular-text" />
<p class="description">Required when enabled. HTTP and HTTPS URLs are accepted; HTTPS is preferred.</p>
</td>
</tr>

<tr>
<th>Audience</th>
<td>
<?php foreach (ll706_auth_api_dashboard_form_audience_choices() as $value => $label) : ?>
  <label style="display: block; margin-bottom: 4px;">
    <input type="checkbox" name="ll706_dashboard_form_config[audience][]" value="<?php echo esc_attr($value); ?>" <?php checked(in_array($value, $dashboard_form_audiences, true)); ?> />
    <?php echo esc_html($label); ?>
  </label>
<?php endforeach; ?>
<p class="description">The app also recognizes compatible audience aliases such as all_members, administrator, executive, and chairman.</p>
</td>
</tr>

<?php if (!empty($dashboard_form['updated_at'])) : ?>
<tr>
<th>Last Updated</th>
<td><code><?php echo esc_html($dashboard_form['updated_at']); ?></code></td>
</tr>
<?php endif; ?>

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

<tr>
<th>Login Log Retention (days)</th>
<td>
<input type="number" min="0" name="ll706_auth_api_options[login_log_retention_days]" value="<?php echo esc_attr($opts['login_log_retention_days']); ?>" />
<p class="description">
How long to keep login log rows before daily cleanup removes them. Set to <code>0</code> to disable automatic cleanup.
</p>
</td>
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
<?php
}

function ll706_auth_api_render_history_tab($login_summaries) {
  $work_log_total_count = ll706_auth_api_get_table_count(ll706_auth_work_logs_table_name());
?>
<h2>Login History</h2>
<p>Each user appears once with their most recent successful app login. "Active" means their latest issued token has not expired or been invalidated.</p>

<?php if (empty($login_summaries)) : ?>
  <p>No app logins have been recorded yet.</p>
<?php else : ?>
  <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin: 0 0 12px;">
    <input type="hidden" name="action" value="ll706_export_login_summary" />
    <?php wp_nonce_field('ll706_export_login_summary'); ?>
    <button class="button button-secondary" type="submit">Export CSV</button>
  </form>

  <table class="widefat striped">
    <thead>
      <tr>
        <th>User</th>
        <th>Email</th>
        <th>Role</th>
        <th>Last Login</th>
        <th>Status</th>
        <th>IP Address</th>
        <th>User Agent</th>
      </tr>
    </thead>
    <tbody>
      <?php foreach ($login_summaries as $entry) : ?>
        <tr>
          <td>
            <?php echo esc_html($entry['username']); ?>
            <?php if (!empty($entry['user_id'])) : ?>
              <br />
              <span class="description">User ID: <?php echo esc_html($entry['user_id']); ?></span>
            <?php endif; ?>
          </td>
          <td><?php echo esc_html($entry['email']); ?></td>
          <td><?php echo esc_html($entry['role']); ?></td>
          <td><?php echo esc_html(get_date_from_gmt($entry['logged_in_at'], 'Y-m-d H:i:s')); ?></td>
          <td><?php echo esc_html(ll706_auth_api_get_login_status_label($entry)); ?></td>
          <td><?php echo esc_html($entry['ip_address'] ?: 'Unknown'); ?></td>
          <td><?php echo esc_html($entry['user_agent'] ?: 'Unknown'); ?></td>
        </tr>
      <?php endforeach; ?>
    </tbody>
  </table>

  <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top: 12px;">
    <input type="hidden" name="action" value="ll706_clear_login_log" />
    <?php wp_nonce_field('ll706_clear_login_log'); ?>
    <button class="button button-secondary" type="submit">Clear Login Log</button>
  </form>
<?php endif; ?>

<table class="widefat striped" style="max-width: 700px; margin-top: 16px;">
  <tbody>
    <tr>
      <th style="width: 240px;">Work Log DB Count</th>
      <td><?php echo esc_html(number_format_i18n($work_log_total_count)); ?></td>
    </tr>
  </tbody>
</table>
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
  if (!current_user_can('edit_user', $user_id)) return;
  check_admin_referer('update-user_' . $user_id);
  if (!isset($_POST['ll706_approved_status'])) return;

  $status = sanitize_text_field(wp_unslash($_POST['ll706_approved_status']));
  if (!in_array($status, ['approved', 'pending', 'auto'], true)) return;

  ll706_auth_api_update_user_access_status($user_id, $status);
}

/**
 * =====================================================
 * REST ROUTES
 * =====================================================
 */
add_action('rest_api_init', function () {
  register_rest_route('ll706/v1', '/dashboard-form', [
    'methods'  => 'GET',
    'callback' => 'll706_auth_api_dashboard_form_response',
    'permission_callback' => '__return_true',
  ]);

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
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);

  register_rest_route('ll706/v1', '/work-log', [
    'methods'  => 'GET',
    'callback' => 'll706_auth_work_log_get',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);

  register_rest_route('ll706/v1', '/work-log', [
    'methods'  => 'POST',
    'callback' => 'll706_auth_work_log_create',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);

  register_rest_route('ll706/v1', '/work-log/(?P<entry_uuid>[a-zA-Z0-9-]+)', [
    'methods'  => 'PUT',
    'callback' => 'll706_auth_work_log_update',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
  ]);

  register_rest_route('ll706/v1', '/work-log/(?P<entry_uuid>[a-zA-Z0-9-]+)', [
    'methods'  => 'DELETE',
    'callback' => 'll706_auth_work_log_delete',
    'permission_callback' => 'll706_auth_api_require_bearer_token',
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

function ll706_auth_error_response(WP_Error $error) {
  $data = $error->get_error_data();
  $status = is_array($data) && isset($data['status']) ? (int) $data['status'] : 400;

  $payload = [
    'ok' => false,
    'error' => $error->get_error_code(),
    'error_code' => $error->get_error_code(),
    'message' => $error->get_error_message(),
  ];

  if (is_array($data)) {
    foreach (['lockout_minutes', 'lockout_until', 'failed_attempts', 'remaining_attempts', 'max_attempts'] as $key) {
      if (isset($data[$key])) {
        $payload[$key] = $data[$key];
      }
    }
  }

  return new WP_REST_Response($payload, $status);
}

function ll706_auth_api_json_error($error_code, $message, $status = 400, array $extra = []) {
  $payload = array_merge([
    'ok' => false,
    'message' => $message,
    'error_code' => $error_code,
    // Backward-compatible alias for existing clients that read "error".
    'error' => $error_code,
  ], $extra);

  return new WP_REST_Response($payload, $status);
}

function ll706_auth_api_login_max_attempts() {
  return 8;
}

function ll706_auth_api_login_lockout_minutes() {
  return 30;
}

function ll706_auth_api_login_lockout_seconds() {
  return ll706_auth_api_login_lockout_minutes() * MINUTE_IN_SECONDS;
}

function ll706_auth_api_login_attempt_key() {
  $ip = ll706_auth_api_get_request_ip_for_wordfence();
  if ($ip === '') {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : 'unknown';
  }

  return 'll706_login_attempts_' . hash('sha256', $ip);
}

function ll706_auth_api_get_login_attempt_state() {
  $state = get_transient(ll706_auth_api_login_attempt_key());
  if (!is_array($state)) {
    return [
      'failed_attempts' => 0,
      'lockout_until_ts' => 0,
    ];
  }

  $lockout_until = isset($state['lockout_until_ts']) ? (int) $state['lockout_until_ts'] : 0;
  if ($lockout_until > 0 && $lockout_until <= time()) {
    ll706_auth_api_clear_login_attempts();
    return [
      'failed_attempts' => 0,
      'lockout_until_ts' => 0,
    ];
  }

  return [
    'failed_attempts' => max(0, (int) ($state['failed_attempts'] ?? 0)),
    'lockout_until_ts' => $lockout_until,
  ];
}

function ll706_auth_api_login_attempt_counts($state = null, $locked = false) {
  if ($state === null) {
    $state = ll706_auth_api_get_login_attempt_state();
  }
  if (!is_array($state)) {
    $state = [
      'failed_attempts' => 0,
      'lockout_until_ts' => 0,
    ];
  }

  $max_attempts = ll706_auth_api_login_max_attempts();
  $failed_attempts = min($max_attempts, max(0, (int) ($state['failed_attempts'] ?? 0)));

  if ($locked) {
    $failed_attempts = max($failed_attempts, $max_attempts);
  }

  return [
    'failed_attempts' => $failed_attempts,
    'remaining_attempts' => max(0, $max_attempts - $failed_attempts),
    'max_attempts' => $max_attempts,
  ];
}

function ll706_auth_api_record_login_failure() {
  $state = ll706_auth_api_get_login_attempt_state();
  if (!empty($state['lockout_until_ts']) && $state['lockout_until_ts'] > time()) {
    return $state;
  }

  $max_attempts = ll706_auth_api_login_max_attempts();
  $state['failed_attempts'] = min($max_attempts, ((int) $state['failed_attempts']) + 1);

  if ($state['failed_attempts'] >= $max_attempts) {
    $state['lockout_until_ts'] = time() + ll706_auth_api_login_lockout_seconds();
  }

  set_transient(ll706_auth_api_login_attempt_key(), $state, ll706_auth_api_login_lockout_seconds());

  return $state;
}

function ll706_auth_api_clear_login_attempts() {
  delete_transient(ll706_auth_api_login_attempt_key());
}

function ll706_auth_api_get_plugin_lockout() {
  $state = ll706_auth_api_get_login_attempt_state();
  $lockout_until = (int) ($state['lockout_until_ts'] ?? 0);
  if ($lockout_until <= time()) {
    return null;
  }

  return array_merge([
    'lockout_minutes' => max(1, (int) ceil(($lockout_until - time()) / MINUTE_IN_SECONDS)),
    'lockout_until' => gmdate('Y-m-d\TH:i:s\Z', $lockout_until),
  ], ll706_auth_api_login_attempt_counts($state, true));
}

function ll706_auth_api_is_login_request() {
  $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? ''));
  if ($method !== 'POST') {
    return false;
  }

  $uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
  $path = parse_url($uri, PHP_URL_PATH);
  if (!is_string($path)) {
    return false;
  }

  if ((bool) preg_match('#/wp-json/ll706/v1/login/?$#', $path)) {
    return true;
  }

  $rest_route = isset($_GET['rest_route']) ? trim((string) wp_unslash($_GET['rest_route']), '/') : '';
  return $rest_route === 'll706/v1/login';
}

function ll706_auth_api_start_wordfence_login_buffer() {
  static $started = false;

  if ($started) {
    return;
  }

  if (!ll706_auth_api_is_login_request()) {
    return;
  }

  $started = true;
  ob_start('ll706_auth_api_maybe_convert_wordfence_lockout_html');
}

function ll706_auth_api_maybe_convert_wordfence_lockout_html($body) {
  if (!ll706_auth_api_is_login_request()) {
    return $body;
  }

  $status = (int) http_response_code();
  $looks_like_wordfence_lockout = (
    stripos($body, 'Wordfence') !== false
    && (
      stripos($body, 'temporarily locked out') !== false
      || stripos($body, 'too many failed login attempts') !== false
      || stripos($body, 'access to this site has been limited') !== false
    )
  );

  if (!in_array($status, [403, 503], true) || !$looks_like_wordfence_lockout) {
    return $body;
  }

  $payload = ll706_auth_api_lockout_payload(ll706_auth_api_get_wordfence_lockout());

  if (!headers_sent()) {
    status_header(429);
    header_remove('Content-Type');
    header('Content-Type: application/json; charset=' . get_option('blog_charset'));
    nocache_headers();
  }

  return wp_json_encode($payload);
}

function ll706_auth_api_lockout_payload($lockout = null) {
  $payload = [
    'ok' => false,
    'message' => 'Too many failed login attempts. Please try again later.',
    'error_code' => 'login_locked',
    // Backward-compatible alias for existing clients that read "error".
    'error' => 'login_locked',
  ];

  if (is_array($lockout)) {
    if (!empty($lockout['lockout_minutes'])) {
      $minutes = (int) $lockout['lockout_minutes'];
      $payload['lockout_minutes'] = $minutes;
      $payload['message'] = sprintf(
        'Too many failed login attempts. Try again in %s.',
        ll706_auth_api_format_lockout_duration($minutes)
      );
    }

    if (!empty($lockout['lockout_until'])) {
      $payload['lockout_until'] = $lockout['lockout_until'];
    }

    foreach (['failed_attempts', 'remaining_attempts', 'max_attempts'] as $key) {
      if (isset($lockout[$key])) {
        $payload[$key] = (int) $lockout[$key];
      }
    }
  }

  if (!isset($payload['failed_attempts'], $payload['remaining_attempts'], $payload['max_attempts'])) {
    $payload = array_merge($payload, ll706_auth_api_login_attempt_counts(null, true));
  }

  return $payload;
}

function ll706_auth_api_lockout_response($lockout = null) {
  $payload = ll706_auth_api_lockout_payload($lockout);

  return ll706_auth_api_json_error(
    'login_locked',
    $payload['message'],
    429,
    array_diff_key($payload, array_flip(['ok', 'message', 'error_code', 'error']))
  );
}

function ll706_auth_api_format_lockout_duration($minutes) {
  $minutes = max(1, (int) $minutes);

  if ($minutes >= 60 && $minutes % 60 === 0) {
    $hours = (int) ($minutes / 60);
    return $hours . ' ' . ($hours === 1 ? 'hour' : 'hours');
  }

  return $minutes . ' ' . ($minutes === 1 ? 'minute' : 'minutes');
}

function ll706_auth_api_get_wordfence_lockout() {
  global $wpdb;

  $ip = ll706_auth_api_get_request_ip_for_wordfence();
  if ($ip === '') {
    return null;
  }

  if (class_exists('wfBlock') && method_exists('wfBlock', 'lockoutForIP')) {
    $block = wfBlock::lockoutForIP($ip);
    if ($block) {
      return ll706_auth_api_normalize_wordfence_lockout([
        'reason' => isset($block->reason) ? $block->reason : '',
        'expiration' => isset($block->expiration) ? $block->expiration : 0,
      ]);
    }
  }

  $table = ll706_auth_api_get_wordfence_blocks_table();
  if ($table === '') {
    return null;
  }

  $ip_sql = '';
  if (class_exists('wfDB') && class_exists('wfUtils') && method_exists('wfUtils', 'inet_pton') && method_exists('wfDB', 'binaryValueToSQLHex')) {
    $ip_sql = wfDB::binaryValueToSQLHex(wfUtils::inet_pton($ip));
  }

  if ($ip_sql !== '') {
    $row = $wpdb->get_row(
      $wpdb->prepare(
        "SELECT `reason`, `blockedTime`, `expiration` FROM `{$table}` WHERE `type` = %d AND `IP` = {$ip_sql} AND (`expiration` = 0 OR `expiration` > UNIX_TIMESTAMP()) ORDER BY `id` DESC LIMIT 1",
        7
      ),
      ARRAY_A
    );
  } else {
    $row = $wpdb->get_row(
      $wpdb->prepare(
        "SELECT `reason`, `blockedTime`, `expiration` FROM `{$table}` WHERE `type` = %d AND `IP` = INET6_ATON(%s) AND (`expiration` = 0 OR `expiration` > UNIX_TIMESTAMP()) ORDER BY `id` DESC LIMIT 1",
        7,
        $ip
      ),
      ARRAY_A
    );
  }

  if (!is_array($row)) {
    return null;
  }

  return ll706_auth_api_normalize_wordfence_lockout($row);
}

function ll706_auth_api_normalize_wordfence_lockout(array $row) {
  $lockout = [
    'reason' => sanitize_text_field((string) ($row['reason'] ?? '')),
  ];

  $expiration = isset($row['expiration']) ? (int) $row['expiration'] : 0;
  if ($expiration > time()) {
    $lockout['lockout_minutes'] = max(1, (int) ceil(($expiration - time()) / MINUTE_IN_SECONDS));
    $lockout['lockout_until'] = gmdate('Y-m-d\TH:i:s\Z', $expiration);
  }

  return $lockout;
}

function ll706_auth_api_get_request_ip_for_wordfence() {
  if (class_exists('wfUtils') && method_exists('wfUtils', 'getIP')) {
    $ip = wfUtils::getIP();
    return is_string($ip) ? $ip : '';
  }

  return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
}

function ll706_auth_api_get_wordfence_blocks_table() {
  global $wpdb;

  $candidates = array_unique([
    $wpdb->prefix . 'wfblocks7',
    $wpdb->prefix . 'wfBlocks7',
    $wpdb->base_prefix . 'wfblocks7',
    $wpdb->base_prefix . 'wfBlocks7',
    $wpdb->prefix . 'wfBlocks',
    $wpdb->base_prefix . 'wfBlocks',
  ]);

  foreach ($candidates as $table) {
    $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
    if ($found === $table) {
      return $table;
    }
  }

  return '';
}

function ll706_auth_api_require_bearer_token(WP_REST_Request $req) {
  $payload = ll706_auth_get_current_user_from_request($req);
  return is_wp_error($payload) ? $payload : true;
}

function ll706_auth_get_current_user_from_request(WP_REST_Request $req) {
  $auth = $req->get_header('authorization');
  if (!$auth || !preg_match('/Bearer\s(\S+)/', $auth, $matches)) {
    return new WP_Error('missing_token', 'Authorization bearer token is required.', ['status' => 401]);
  }

  try {
    $payload = ll706_jwt_decode($matches[1]);
  } catch (Exception $e) {
    return new WP_Error('invalid_token', 'The provided token is invalid.', ['status' => 401]);
  }

  $opts = ll706_auth_api_get_options();
  if ((int) ($payload['ver'] ?? 0) !== (int) $opts['token_version']) {
    return new WP_Error('invalidated', 'The provided token has been invalidated.', ['status' => 401]);
  }

  $user_id = isset($payload['data']['user_id']) ? (int) $payload['data']['user_id'] : 0;
  if ($user_id < 1 || !get_user_by('id', $user_id)) {
    return new WP_Error('invalid_user', 'The user for this token could not be found.', ['status' => 401]);
  }

  return $payload;
}

/**
 * =====================================================
 * LOGIN + ME
 * =====================================================
 */
function ll706_auth_login(WP_REST_Request $req) {
  $opts = ll706_auth_api_get_options();

  $plugin_lockout = ll706_auth_api_get_plugin_lockout();
  if (is_array($plugin_lockout)) {
    return ll706_auth_api_lockout_response($plugin_lockout);
  }

  $wordfence_lockout = ll706_auth_api_get_wordfence_lockout();
  if (is_array($wordfence_lockout)) {
    return ll706_auth_api_lockout_response($wordfence_lockout);
  }

  $raw_username = trim((string) wp_unslash($req->get_param('username')));
  $password     = (string) wp_unslash($req->get_param('password'));

  if ($raw_username === '' || $password === '') {
    return ll706_auth_api_json_error(
      'missing_credentials',
      'Username and password are required.',
      400
    );
  }

  // Allow login by email OR username (hardened)
  $username = $raw_username;
  if (is_email($username)) {
    $user_obj = get_user_by('email', $username);

    if (!$user_obj) {
      $attempt_state = ll706_auth_api_record_login_failure();
      if (!empty($attempt_state['lockout_until_ts']) && $attempt_state['lockout_until_ts'] > time()) {
        return ll706_auth_api_lockout_response(ll706_auth_api_get_plugin_lockout());
      }

      return ll706_auth_api_json_error(
        'invalid_credentials',
        'Invalid username or password.',
        401,
        ll706_auth_api_login_attempt_counts($attempt_state)
      );
    }

    $username = $user_obj->user_login;
  }

  $user = wp_authenticate($username, $password);

  if (is_wp_error($user)) {
    $attempt_state = ll706_auth_api_record_login_failure();

    $wordfence_lockout = ll706_auth_api_get_wordfence_lockout();
    if (is_array($wordfence_lockout)) {
      return ll706_auth_api_lockout_response(array_merge(
        $wordfence_lockout,
        ll706_auth_api_login_attempt_counts($attempt_state, true)
      ));
    }

    if (!empty($attempt_state['lockout_until_ts']) && $attempt_state['lockout_until_ts'] > time()) {
      return ll706_auth_api_lockout_response(ll706_auth_api_get_plugin_lockout());
    }

    return ll706_auth_api_json_error(
      'invalid_credentials',
      'Invalid username or password.',
      401,
      ll706_auth_api_login_attempt_counts($attempt_state)
    );
  }

  ll706_auth_api_clear_login_attempts();

  $approval_meta_key = $opts['approved_meta_key'];

  // Administrators are always approved
  if (in_array('administrator', (array) $user->roles, true)) {
      update_user_meta($user->ID, $approval_meta_key, 1);
  } else {
      if (!ll706_auth_api_is_user_approved($user->ID)) {
          return ll706_auth_api_json_error(
              'not_approved',
              'Your account is pending approval.',
              403
          );
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
  $payload['data']['seniority_date'] =
    $meta['Seniority_Date'][0]
    ?? ($meta['SeniorityDate'][0] ?? ($meta['seniority_date'][0] ?? null));

  ll706_auth_api_record_login($user, $role, $payload['exp'], $opts['token_version']);

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

  $username = sanitize_user(wp_unslash((string) $req->get_param('username')), true);
  $email    = sanitize_email(wp_unslash((string) $req->get_param('email')));
  $password = (string) wp_unslash($req->get_param('password'));

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
    'first_name' => sanitize_text_field(wp_unslash($req->get_param('first_name'))),
    'last_name'  => sanitize_text_field(wp_unslash($req->get_param('last_name'))),
  ]);

  // Normalize email opt-in
  $email_opt_in = in_array(
    strtolower((string) wp_unslash($req->get_param('email_opt_in'))),
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
    'Seniority_Date'   => 'seniority_date',
  ];

  foreach ($meta_map as $meta_key => $param) {
    if ($req->get_param($param) !== null) {
      update_user_meta(
        $user_id,
        $meta_key,
        sanitize_text_field(wp_unslash($req->get_param($param)))
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
  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) {
    return ll706_auth_error_response($payload);
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
  $user['seniority_date'] =
    $meta['Seniority_Date'][0]
    ?? ($meta['SeniorityDate'][0] ?? ($meta['seniority_date'][0] ?? null));

  return new WP_REST_Response([
    'ok' => true,
    'user' => $user,
    'expires_at' => $payload['exp']
  ], 200);
}

function ll706_auth_normalize_bool($value) {
  if (is_bool($value)) {
    return $value;
  }

  if (is_numeric($value)) {
    return (int) $value === 1;
  }

  $normalized = strtolower(trim((string) $value));
  return in_array($normalized, ['1', 'true', 'yes', 'on'], true);
}

function ll706_auth_sanitize_text_list($value) {
  if ($value === null || $value === '') {
    return [];
  }

  if (!is_array($value)) {
    $value = [$value];
  }

  $sanitized = [];
  foreach ($value as $item) {
    if (is_array($item) || is_object($item)) {
      continue;
    }

    $text = sanitize_text_field(wp_unslash((string) $item));
    if ($text !== '') {
      $sanitized[] = $text;
    }
  }

  return array_values(array_unique($sanitized));
}

function ll706_auth_allowed_follow_up_colors() {
  return ['red', 'orange', 'yellow', 'green', 'blue', 'purple'];
}

function ll706_auth_sanitize_follow_up_color($value) {
  if ($value === null || is_array($value) || is_object($value)) {
    return null;
  }

  $color = strtolower(sanitize_text_field(wp_unslash((string) $value)));
  return in_array($color, ll706_auth_allowed_follow_up_colors(), true) ? $color : null;
}

function ll706_auth_sanitize_work_log_item($item) {
  if (is_scalar($item)) {
    $label = sanitize_text_field(wp_unslash((string) $item));
    return $label !== '' ? ['label' => $label, 'follow_up_color' => null] : null;
  }

  if (!is_array($item)) {
    return null;
  }

  $normalized_item = [];
  $follow_up_color = null;

  foreach ($item as $key => $value) {
    $clean_key = sanitize_key((string) $key);
    if ($clean_key === '') {
      continue;
    }

    if ($clean_key === 'follow_up_color') {
      $follow_up_color = ll706_auth_sanitize_follow_up_color($value);
      continue;
    }

    if (is_bool($value) || is_numeric($value)) {
      $normalized_item[$clean_key] = $value;
    } elseif (is_string($value)) {
      $normalized_item[$clean_key] = sanitize_text_field(wp_unslash($value));
    } elseif (is_array($value)) {
      $normalized_item[$clean_key] = ll706_auth_sanitize_text_list($value);
    }
  }

  if (empty($normalized_item) && $follow_up_color === null) {
    return null;
  }

  $normalized_item['follow_up_color'] = $follow_up_color;

  return $normalized_item;
}

function ll706_auth_format_work_log_item($item) {
  $normalized_item = ll706_auth_sanitize_work_log_item($item);
  if ($normalized_item === null) {
    return null;
  }

  if (!array_key_exists('follow_up_color', $normalized_item)) {
    $normalized_item['follow_up_color'] = null;
  }

  return $normalized_item;
}

function ll706_auth_normalize_work_log_shift($shift) {
  $shift = sanitize_text_field(wp_unslash((string) $shift));
  if ($shift === '') {
    return '';
  }

  $normalized = strtolower(trim($shift));
  $map = [
    '1' => '1st',
    '1st' => '1st',
    'first' => '1st',
    '2' => '2nd',
    '2nd' => '2nd',
    'second' => '2nd',
    '3' => '3rd',
    '3rd' => '3rd',
    'third' => '3rd',
  ];

  return $map[$normalized] ?? substr($shift, 0, 20);
}

function ll706_auth_validate_work_log_payload(WP_REST_Request $req, $entry_uuid = null) {
  $work_date = sanitize_text_field(wp_unslash((string) $req->get_param('work_date')));
  $shift = ll706_auth_normalize_work_log_shift($req->get_param('shift'));
  $supervisor = $req->get_param('supervisor');
  $notes = $req->get_param('notes');
  $worked_with = $req->get_param('worked_with');
  $work_items = $req->get_param('work_items');

  if ($entry_uuid === null) {
    $entry_uuid = sanitize_text_field(wp_unslash((string) $req->get_param('entry_uuid')));
    if ($entry_uuid === '') {
      $entry_uuid = wp_generate_uuid4();
    }
  }

  if (!preg_match('/^[a-zA-Z0-9-]{1,36}$/', $entry_uuid)) {
    return new WP_Error('invalid_entry_uuid', 'A valid entry UUID is required.', ['status' => 400]);
  }

  if ($work_date === '' || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $work_date)) {
    return new WP_Error('invalid_work_date', 'work_date must use YYYY-MM-DD format.', ['status' => 400]);
  }

  $date = DateTime::createFromFormat('Y-m-d', $work_date);
  if (!$date || $date->format('Y-m-d') !== $work_date) {
    return new WP_Error('invalid_work_date', 'work_date must be a valid calendar date.', ['status' => 400]);
  }

  if ($shift === '') {
    return new WP_Error('invalid_shift', 'shift is required.', ['status' => 400]);
  }

  if (!is_array($work_items) || empty($work_items)) {
    return new WP_Error('invalid_work_items', 'work_items must be a non-empty array.', ['status' => 400]);
  }

  $normalized_work_items = [];
  foreach ($work_items as $item) {
    $normalized_item = ll706_auth_sanitize_work_log_item($item);
    if ($normalized_item !== null) {
      $normalized_work_items[] = $normalized_item;
    }
  }

  if (empty($normalized_work_items)) {
    return new WP_Error('invalid_work_items', 'work_items must include at least one usable item.', ['status' => 400]);
  }

  return [
    'entry_uuid'  => $entry_uuid,
    'work_date'   => $work_date,
    'shift'       => $shift,
    'doubled'     => ll706_auth_normalize_bool($req->get_param('doubled')) ? 1 : 0,
    'supervisor'  => $supervisor !== null ? sanitize_textarea_field(wp_unslash((string) $supervisor)) : null,
    'worked_with' => wp_json_encode(ll706_auth_sanitize_text_list($worked_with)),
    'notes'       => $notes !== null ? sanitize_textarea_field(wp_unslash((string) $notes)) : null,
    'work_items'  => wp_json_encode(array_values($normalized_work_items)),
  ];
}

function ll706_auth_format_work_log_row($row) {
  if (!is_array($row)) {
    return [];
  }

  $worked_with = json_decode($row['worked_with'] ?? '[]', true);
  $work_items = json_decode($row['work_items'] ?? '[]', true);
  $formatted_work_items = [];
  if (is_array($work_items)) {
    foreach ($work_items as $item) {
      $formatted_item = ll706_auth_format_work_log_item($item);
      if ($formatted_item !== null) {
        $formatted_work_items[] = $formatted_item;
      }
    }
  }

  return [
    'entry_uuid'  => (string) ($row['entry_uuid'] ?? ''),
    'work_date'   => (string) ($row['work_date'] ?? ''),
    'shift'       => ll706_auth_normalize_work_log_shift($row['shift'] ?? ''),
    'doubled'     => !empty($row['doubled']),
    'supervisor'  => isset($row['supervisor']) ? (string) $row['supervisor'] : null,
    'worked_with' => is_array($worked_with) ? $worked_with : [],
    'notes'       => isset($row['notes']) ? (string) $row['notes'] : null,
    'work_items'  => $formatted_work_items,
    'created_at'  => $row['created_at'] ?? null,
    'updated_at'  => $row['updated_at'] ?? null,
    'deleted_at'  => $row['deleted_at'] ?? null,
  ];
}

function ll706_auth_get_formatted_work_log_entry($user_id, $entry_uuid) {
  global $wpdb;

  $table = ll706_auth_work_logs_table_name();
  $row = $wpdb->get_row(
    $wpdb->prepare(
      "SELECT * FROM {$table} WHERE user_id = %d AND entry_uuid = %s AND deleted_at IS NULL LIMIT 1",
      (int) $user_id,
      (string) $entry_uuid
    ),
    ARRAY_A
  );

  if (!$row) {
    return null;
  }

  return ll706_auth_format_work_log_row($row);
}

function ll706_auth_work_log_get(WP_REST_Request $req) {
  global $wpdb;

  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) {
    return ll706_auth_error_response($payload);
  }

  $user_id = (int) $payload['data']['user_id'];
  $table = ll706_auth_work_logs_table_name();
  $rows = $wpdb->get_results(
    $wpdb->prepare(
      "SELECT * FROM {$table} WHERE user_id = %d AND deleted_at IS NULL ORDER BY work_date DESC, created_at DESC",
      $user_id
    ),
    ARRAY_A
  );

  return new WP_REST_Response([
    'ok' => true,
    'entries' => array_map('ll706_auth_format_work_log_row', $rows ?: []),
  ], 200);
}

function ll706_auth_work_log_create(WP_REST_Request $req) {
  global $wpdb;

  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) {
    return ll706_auth_error_response($payload);
  }

  $entry = ll706_auth_validate_work_log_payload($req);
  if (is_wp_error($entry)) {
    return ll706_auth_error_response($entry);
  }

  $user_id = (int) $payload['data']['user_id'];
  $inserted = $wpdb->insert(
    ll706_auth_work_logs_table_name(),
    array_merge(['user_id' => $user_id], $entry),
    ['%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s']
  );

  if ($inserted === false) {
    $status = strpos((string) $wpdb->last_error, 'Duplicate entry') !== false ? 409 : 500;
    $message = $status === 409 ? 'A work-log entry with this UUID already exists.' : 'Unable to create work-log entry.';
    return ll706_auth_error_response(new WP_Error('work_log_create_failed', $message, ['status' => $status]));
  }

  $formatted = ll706_auth_get_formatted_work_log_entry($user_id, $entry['entry_uuid']);
  if ($formatted === null) {
    return ll706_auth_error_response(new WP_Error('work_log_create_failed', 'Work-log entry was created but could not be loaded.', ['status' => 500]));
  }

  return new WP_REST_Response([
    'ok' => true,
    'entry' => $formatted,
  ], 201);
}

function ll706_auth_work_log_update(WP_REST_Request $req) {
  global $wpdb;

  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) {
    return ll706_auth_error_response($payload);
  }

  $entry_uuid = sanitize_text_field(wp_unslash((string) $req['entry_uuid']));
  $entry = ll706_auth_validate_work_log_payload($req, $entry_uuid);
  if (is_wp_error($entry)) {
    return ll706_auth_error_response($entry);
  }

  $user_id = (int) $payload['data']['user_id'];
  $table = ll706_auth_work_logs_table_name();
  $exists = $wpdb->get_var(
    $wpdb->prepare(
      "SELECT id FROM {$table} WHERE user_id = %d AND entry_uuid = %s AND deleted_at IS NULL LIMIT 1",
      $user_id,
      $entry_uuid
    )
  );

  if (!$exists) {
    return ll706_auth_error_response(new WP_Error('work_log_not_found', 'Work-log entry was not found.', ['status' => 404]));
  }

  $updated = $wpdb->update(
    $table,
    $entry,
    ['user_id' => $user_id, 'entry_uuid' => $entry_uuid, 'deleted_at' => null],
    ['%s', '%s', '%d', '%s', '%s', '%s', '%s'],
    ['%d', '%s', '%s']
  );

  if ($updated === false) {
    return ll706_auth_error_response(new WP_Error('work_log_update_failed', 'Unable to update work-log entry.', ['status' => 500]));
  }

  $formatted = ll706_auth_get_formatted_work_log_entry($user_id, $entry_uuid);
  if ($formatted === null) {
    return ll706_auth_error_response(new WP_Error('work_log_not_found', 'Work-log entry was not found after update.', ['status' => 404]));
  }

  return new WP_REST_Response([
    'ok' => true,
    'entry' => $formatted,
  ], 200);
}

function ll706_auth_work_log_delete(WP_REST_Request $req) {
  global $wpdb;

  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) {
    return ll706_auth_error_response($payload);
  }

  $user_id = (int) $payload['data']['user_id'];
  $entry_uuid = sanitize_text_field(wp_unslash((string) $req['entry_uuid']));
  $deleted = $wpdb->update(
    ll706_auth_work_logs_table_name(),
    ['deleted_at' => current_time('mysql')],
    ['user_id' => $user_id, 'entry_uuid' => $entry_uuid, 'deleted_at' => null],
    ['%s'],
    ['%d', '%s', '%s']
  );

  if ($deleted === false) {
    return ll706_auth_error_response(new WP_Error('work_log_delete_failed', 'Unable to delete work-log entry.', ['status' => 500]));
  }

  if ($deleted === 0) {
    return ll706_auth_error_response(new WP_Error('work_log_not_found', 'Work-log entry was not found.', ['status' => 404]));
  }

  return new WP_REST_Response(['ok' => true], 200);
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
