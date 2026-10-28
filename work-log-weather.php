<?php
/**
 * Shared, date-based weather for AskBruno work logs.
 * No work-log contents or member locations are sent to Open-Meteo.
 */

if (!defined('ABSPATH')) exit;

if (!defined('LL706_AUTH_WEATHER_DB_VERSION')) {
  define('LL706_AUTH_WEATHER_DB_VERSION', '1.0.0');
}

if (!defined('LL706_AUTH_WEATHER_SITE')) {
  define('LL706_AUTH_WEATHER_SITE', 'barstow-lmit');
}

if (!defined('LL706_AUTH_WEATHER_TIMEZONE')) {
  define('LL706_AUTH_WEATHER_TIMEZONE', 'America/Los_Angeles');
}

// 200 North Avenue H, Barstow, CA 92311. This is a fixed worksite, never device GPS.
if (!defined('LL706_AUTH_WEATHER_LATITUDE')) {
  define('LL706_AUTH_WEATHER_LATITUDE', 34.8936737);
}
if (!defined('LL706_AUTH_WEATHER_LONGITUDE')) {
  define('LL706_AUTH_WEATHER_LONGITUDE', -117.0476200);
}

function ll706_auth_weather_table_name() {
  global $wpdb;
  return $wpdb->prefix . 'll706_weather_days';
}

function ll706_auth_weather_today() {
  return (new DateTimeImmutable('now', new DateTimeZone(LL706_AUTH_WEATHER_TIMEZONE)))->format('Y-m-d');
}

function ll706_auth_weather_yesterday() {
  return (new DateTimeImmutable('yesterday', new DateTimeZone(LL706_AUTH_WEATHER_TIMEZONE)))->format('Y-m-d');
}

function ll706_auth_weather_valid_date($date) {
  if (!is_string($date) || !preg_match('/^\d{4}-\d{2}-\d{2}$/D', $date)) {
    return false;
  }
  $parsed = DateTimeImmutable::createFromFormat('!Y-m-d', $date, new DateTimeZone(LL706_AUTH_WEATHER_TIMEZONE));
  return $parsed !== false && $parsed->format('Y-m-d') === $date;
}

function ll706_auth_weather_setup_table() {
  global $wpdb;
  require_once ABSPATH . 'wp-admin/includes/upgrade.php';

  $table = ll706_auth_weather_table_name();
  $charset_collate = $wpdb->get_charset_collate();
  $sql = "CREATE TABLE {$table} (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    site_key varchar(40) NOT NULL,
    weather_date date NOT NULL,
    high_f decimal(5,1) NOT NULL,
    low_f decimal(5,1) NOT NULL,
    humidity_mean_pct tinyint(3) unsigned NOT NULL,
    wind_max_mph decimal(5,1) NOT NULL,
    data_kind varchar(16) NOT NULL,
    model varchar(32) NOT NULL,
    fetched_at datetime NOT NULL,
    PRIMARY KEY  (id),
    UNIQUE KEY site_date (site_key,weather_date)
  ) {$charset_collate};";

  dbDelta($sql);
  $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table)));
  if ($exists !== $table) {
    return false;
  }

  update_option('ll706_auth_weather_db_version', LL706_AUTH_WEATHER_DB_VERSION, false);
  ll706_auth_weather_schedule_backfill();
  return true;
}

function ll706_auth_weather_maybe_setup() {
  if (get_option('ll706_auth_weather_db_version', '') !== LL706_AUTH_WEATHER_DB_VERSION) {
    ll706_auth_weather_setup_table();
  }
}

function ll706_auth_weather_next_daily_timestamp() {
  $zone = new DateTimeZone(LL706_AUTH_WEATHER_TIMEZONE);
  $now = new DateTimeImmutable('now', $zone);
  $next = $now->setTime(9, 0, 0);
  if ($next <= $now) {
    $next = $next->modify('+1 day');
  }
  return $next->getTimestamp();
}

function ll706_auth_weather_ensure_daily_schedule() {
  if (get_option('ll706_auth_weather_db_version', '') !== LL706_AUTH_WEATHER_DB_VERSION) {
    return;
  }
  if (!wp_next_scheduled('ll706_auth_weather_daily')) {
    wp_schedule_single_event(ll706_auth_weather_next_daily_timestamp(), 'll706_auth_weather_daily');
  }
}

function ll706_auth_weather_deactivate() {
  wp_clear_scheduled_hook('ll706_auth_weather_daily');
  wp_clear_scheduled_hook('ll706_auth_weather_backfill');
}

function ll706_auth_weather_schedule_backfill() {
  global $wpdb;
  if (get_option('ll706_auth_weather_backfill_complete', false)) {
    return;
  }
  if (!get_option('ll706_auth_weather_backfill_cursor', false)) {
    // Work Log first shipped in March 2026. Include older server entries if present.
    $first = '2026-03-27';
    $work_logs = ll706_auth_work_logs_table_name();
    $oldest = $wpdb->get_var("SELECT MIN(work_date) FROM {$work_logs} WHERE deleted_at IS NULL");
    if (ll706_auth_weather_valid_date($oldest) && $oldest < $first) {
      $first = $oldest;
    }
    update_option('ll706_auth_weather_backfill_cursor', $first, false);
  }
  if (!wp_next_scheduled('ll706_auth_weather_backfill')) {
    wp_schedule_single_event(time() + MINUTE_IN_SECONDS, 'll706_auth_weather_backfill');
  }
}

function ll706_auth_weather_api_url($start_date, $end_date, $kind) {
  $params = [
    'latitude' => LL706_AUTH_WEATHER_LATITUDE,
    'longitude' => LL706_AUTH_WEATHER_LONGITUDE,
    'start_date' => $start_date,
    'end_date' => $end_date,
    'daily' => 'temperature_2m_max,temperature_2m_min,relative_humidity_2m_mean,wind_speed_10m_max',
    'temperature_unit' => 'fahrenheit',
    'wind_speed_unit' => 'mph',
    'timezone' => LL706_AUTH_WEATHER_TIMEZONE,
  ];
  if ($kind === 'historical') {
    $params['models'] = $start_date >= '2017-01-01' ? 'ecmwf_ifs' : 'era5';
    $base = 'https://archive-api.open-meteo.com/v1/archive';
  } else {
    $base = 'https://api.open-meteo.com/v1/forecast';
  }
  return $base . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
}

function ll706_auth_weather_fetch_range($start_date, $end_date, $kind) {
  if (!ll706_auth_weather_valid_date($start_date) || !ll706_auth_weather_valid_date($end_date) ||
      $end_date < $start_date || !in_array($kind, ['forecast', 'historical'], true)) {
    return new WP_Error('weather_invalid_range', 'Invalid weather date range.');
  }

  $days = (new DateTimeImmutable($start_date))->diff(new DateTimeImmutable($end_date))->days + 1;
  if ($days > 31) {
    return new WP_Error('weather_range_too_large', 'Weather requests are limited to 31 days.');
  }

  $response = wp_safe_remote_get(ll706_auth_weather_api_url($start_date, $end_date, $kind), [
    'timeout' => 15,
    'redirection' => 0,
    'headers' => ['Accept' => 'application/json'],
  ]);
  if (is_wp_error($response)) {
    return $response;
  }
  if (wp_remote_retrieve_response_code($response) !== 200) {
    return new WP_Error('weather_provider_status', 'Weather provider returned a non-success status.');
  }
  $body = wp_remote_retrieve_body($response);
  if (!is_string($body) || strlen($body) > 250000) {
    return new WP_Error('weather_provider_body', 'Invalid weather provider response size.');
  }
  $data = json_decode($body, true);
  if (!is_array($data) || !empty($data['error']) || ($data['timezone'] ?? '') !== LL706_AUTH_WEATHER_TIMEZONE) {
    return new WP_Error('weather_provider_data', 'Invalid weather provider response.');
  }
  $daily = $data['daily'] ?? null;
  $units = $data['daily_units'] ?? null;
  if (!is_array($daily) || !is_array($units) ||
      ($units['temperature_2m_max'] ?? '') !== '°F' ||
      ($units['temperature_2m_min'] ?? '') !== '°F' ||
      ($units['relative_humidity_2m_mean'] ?? '') !== '%' ||
      ($units['wind_speed_10m_max'] ?? '') !== 'mp/h') {
    return new WP_Error('weather_provider_units', 'Unexpected weather provider units.');
  }

  $keys = ['time', 'temperature_2m_max', 'temperature_2m_min', 'relative_humidity_2m_mean', 'wind_speed_10m_max'];
  foreach ($keys as $key) {
    if (!isset($daily[$key]) || !is_array($daily[$key])) {
      return new WP_Error('weather_provider_data', 'Missing weather provider values.');
    }
  }

  $rows = [];
  foreach ($daily['time'] as $index => $date) {
    if (!ll706_auth_weather_valid_date($date) || $date < $start_date || $date > $end_date) {
      continue;
    }
    $high = $daily['temperature_2m_max'][$index] ?? null;
    $low = $daily['temperature_2m_min'][$index] ?? null;
    $humidity = $daily['relative_humidity_2m_mean'][$index] ?? null;
    $wind = $daily['wind_speed_10m_max'][$index] ?? null;
    if (!is_numeric($high) || !is_numeric($low) || !is_numeric($humidity) || !is_numeric($wind)) {
      continue;
    }
    $high = (float) $high;
    $low = (float) $low;
    $humidity = (float) $humidity;
    $wind = (float) $wind;
    if (!is_finite($high) || !is_finite($low) || !is_finite($humidity) || !is_finite($wind) ||
        $high < $low || $high > 150 || $low < -100 || $humidity < 0 || $humidity > 100 || $wind < 0 || $wind > 300) {
      continue;
    }
    $rows[$date] = [
      'site_key' => LL706_AUTH_WEATHER_SITE,
      'weather_date' => $date,
      'high_f' => round($high, 1),
      'low_f' => round($low, 1),
      'humidity_mean_pct' => (int) round($humidity),
      'wind_max_mph' => round($wind, 1),
      'data_kind' => $kind,
      'model' => $kind === 'historical' ? ($start_date >= '2017-01-01' ? 'ecmwf_ifs' : 'era5') : 'best_match',
      'fetched_at' => gmdate('Y-m-d H:i:s'),
    ];
  }
  return $rows ? $rows : new WP_Error('weather_no_data', 'No complete weather days were returned.');
}

function ll706_auth_weather_store_rows($rows) {
  global $wpdb;
  $table = ll706_auth_weather_table_name();
  foreach ($rows as $row) {
    $saved = $wpdb->replace($table, $row, ['%s', '%s', '%f', '%f', '%d', '%f', '%s', '%s', '%s']);
    if ($saved === false) {
      return new WP_Error('weather_database', 'Unable to store weather data.');
    }
  }
  return true;
}

function ll706_auth_weather_get_row($date) {
  global $wpdb;
  $table = ll706_auth_weather_table_name();
  return $wpdb->get_row($wpdb->prepare(
    "SELECT weather_date, high_f, low_f, humidity_mean_pct, wind_max_mph, data_kind, fetched_at
     FROM {$table} WHERE site_key = %s AND weather_date = %s LIMIT 1",
    LL706_AUTH_WEATHER_SITE,
    $date
  ), ARRAY_A);
}

function ll706_auth_weather_refresh_day_if_needed($date) {
  $row = ll706_auth_weather_get_row($date);
  $today = ll706_auth_weather_today();
  if ($row && ($row['data_kind'] ?? '') === 'historical') {
    return $row;
  }
  if ($row && $date === $today && strtotime($row['fetched_at'] . ' UTC') > time() - 6 * HOUR_IN_SECONDS) {
    return $row;
  }

  // A short cooldown prevents repeated provider calls for missing or delayed dates.
  $cooldown_key = 'll706_weather_try_' . md5($date);
  if (get_transient($cooldown_key)) {
    return $row;
  }
  set_transient($cooldown_key, 1, 15 * MINUTE_IN_SECONDS);
  $kind = $date === $today ? 'forecast' : 'historical';
  $fetched = ll706_auth_weather_fetch_range($date, $date, $kind);
  if (!is_wp_error($fetched) && !is_wp_error(ll706_auth_weather_store_rows($fetched))) {
    delete_transient($cooldown_key);
    return ll706_auth_weather_get_row($date);
  }
  return $row;
}

function ll706_auth_weather_run_daily() {
  ll706_auth_weather_ensure_daily_schedule();
  $zone = new DateTimeZone(LL706_AUTH_WEATHER_TIMEZONE);
  $today = new DateTimeImmutable('today', $zone);
  $start = $today->modify('-7 days')->format('Y-m-d');
  $end = $today->modify('-1 day')->format('Y-m-d');
  $historical = ll706_auth_weather_fetch_range($start, $end, 'historical');
  $historical_result = is_wp_error($historical) ? $historical : ll706_auth_weather_store_rows($historical);
  $date = $today->format('Y-m-d');
  $forecast = ll706_auth_weather_fetch_range($date, $date, 'forecast');
  $forecast_result = is_wp_error($forecast) ? $forecast : ll706_auth_weather_store_rows($forecast);

  update_option('ll706_auth_weather_last_run', gmdate('Y-m-d H:i:s'), false);
  update_option('ll706_auth_weather_last_status',
    !is_wp_error($historical_result) && !is_wp_error($forecast_result) ? 'ok' : 'retry_needed', false);
}

function ll706_auth_weather_run_backfill() {
  $cursor = get_option('ll706_auth_weather_backfill_cursor', '');
  if (!ll706_auth_weather_valid_date($cursor)) {
    return;
  }
  $yesterday = ll706_auth_weather_yesterday();
  if ($cursor > $yesterday) {
    delete_option('ll706_auth_weather_backfill_cursor');
    update_option('ll706_auth_weather_backfill_complete', gmdate('Y-m-d H:i:s'), false);
    return;
  }

  $end = (new DateTimeImmutable($cursor))->modify('+29 days')->format('Y-m-d');
  if ($end > $yesterday) {
    $end = $yesterday;
  }
  $rows = ll706_auth_weather_fetch_range($cursor, $end, 'historical');
  // Never mark a backfill chunk complete if the provider omitted a day.
  if (!is_wp_error($rows)) {
    $expected = (new DateTimeImmutable($cursor))->diff(new DateTimeImmutable($end))->days + 1;
    if (count($rows) !== $expected) {
      $rows = new WP_Error('weather_incomplete_range', 'The weather provider omitted one or more days.');
    }
  }
  $result = is_wp_error($rows) ? $rows : ll706_auth_weather_store_rows($rows);
  if (is_wp_error($result)) {
    wp_schedule_single_event(time() + HOUR_IN_SECONDS, 'll706_auth_weather_backfill');
    return;
  }

  $next = (new DateTimeImmutable($end))->modify('+1 day')->format('Y-m-d');
  update_option('ll706_auth_weather_backfill_cursor', $next, false);
  if ($next <= $yesterday) {
    wp_schedule_single_event(time() + MINUTE_IN_SECONDS, 'll706_auth_weather_backfill');
  } else {
    delete_option('ll706_auth_weather_backfill_cursor');
    update_option('ll706_auth_weather_backfill_complete', gmdate('Y-m-d H:i:s'), false);
  }
}

function ll706_auth_weather_rest_get(WP_REST_Request $req) {
  $payload = ll706_auth_get_current_user_from_request($req);
  if (is_wp_error($payload)) {
    return ll706_auth_error_response($payload);
  }

  $date = $req->get_param('date');
  if (!ll706_auth_weather_valid_date($date) || $date < '1940-01-01' || $date > ll706_auth_weather_today()) {
    return ll706_auth_error_response(new WP_Error('weather_invalid_date', 'A valid work date through today is required.', ['status' => 400]));
  }

  $row = ll706_auth_weather_refresh_day_if_needed($date);
  $weather = null;
  if (is_array($row)) {
    $weather = [
      'date' => $row['weather_date'],
      'location' => 'Barstow LMIT',
      'high_f' => (float) $row['high_f'],
      'low_f' => (float) $row['low_f'],
      'humidity_mean_pct' => (int) $row['humidity_mean_pct'],
      'wind_max_mph' => (float) $row['wind_max_mph'],
      'status' => $row['data_kind'],
      'source' => 'Open-Meteo',
      'source_url' => 'https://open-meteo.com/',
      'license_url' => 'https://open-meteo.com/en/licence',
      'fetched_at_utc' => $row['fetched_at'],
    ];
  }
  return new WP_REST_Response(['ok' => true, 'weather' => $weather], 200);
}
