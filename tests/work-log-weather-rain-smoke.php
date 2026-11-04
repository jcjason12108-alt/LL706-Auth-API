<?php
// Run with: php tests/work-log-weather-rain-smoke.php.
define('ABSPATH', __DIR__ . '/');
class WP_Error {
  public $code;
  public function __construct($code) { $this->code = $code; }
}
function is_wp_error($value) { return $value instanceof WP_Error; }
function wp_safe_remote_get($url, $options) {
  $GLOBALS['weather_request_url'] = $url;
  return ['body' => json_encode($GLOBALS['weather_response'])];
}
function wp_remote_retrieve_response_code($response) { return 200; }
function wp_remote_retrieve_body($response) { return $response['body']; }
require dirname(__DIR__) . '/work-log-weather.php';

function check($condition, $message) {
  if (!$condition) throw new RuntimeException($message);
}

$GLOBALS['weather_response'] = [
  'timezone' => 'America/Los_Angeles',
  'daily_units' => [
    'temperature_2m_max' => '°F',
    'temperature_2m_min' => '°F',
    'relative_humidity_2m_mean' => '%',
    'wind_speed_10m_max' => 'mp/h',
    'rain_sum' => 'inch',
  ],
  'daily' => [
    'time' => ['2026-11-01', '2026-11-02'],
    'temperature_2m_max' => [64.3, 70.1],
    'temperature_2m_min' => [47.9, 48.2],
    'relative_humidity_2m_mean' => [65, 41],
    'wind_speed_10m_max' => [22.2, 11.4],
    'rain_sum' => [0.059, 0.0],
  ],
];
$rows = ll706_auth_weather_fetch_range('2026-11-01', '2026-11-02', 'historical');
check(!is_wp_error($rows) && count($rows) === 2, 'Valid rain days were rejected');
check(strpos($GLOBALS['weather_request_url'], 'precipitation_unit=inch') !== false, 'Provider request did not use inches');
check($rows['2026-11-01']['rain_in'] === 0.059, 'Rain amount lost its three-decimal precision');
check(ll706_auth_weather_format_row($rows['2026-11-01'])['did_rain'] === true, 'Rainy day was not reported');
check(ll706_auth_weather_format_row($rows['2026-11-02'])['did_rain'] === false, 'Dry day was reported as rainy');
check(ll706_auth_weather_format_row(['weather_date' => '2026-10-31', 'high_f' => 70, 'low_f' => 50, 'humidity_mean_pct' => 40, 'wind_max_mph' => 10, 'data_kind' => 'historical', 'fetched_at' => '2026-11-01 12:00:00'])['did_rain'] === null, 'Missing rain was treated as dry');

$GLOBALS['weather_response']['daily_units']['rain_sum'] = 'mm';
check(ll706_auth_weather_fetch_range('2026-11-01', '2026-11-02', 'historical')->code === 'weather_provider_units', 'Wrong rain unit was accepted');
$GLOBALS['weather_response']['daily_units']['rain_sum'] = 'inch';
$GLOBALS['weather_response']['daily']['rain_sum'][0] = null;
$partial = ll706_auth_weather_fetch_range('2026-11-01', '2026-11-02', 'historical');
check(!is_wp_error($partial) && !isset($partial['2026-11-01']) && isset($partial['2026-11-02']), 'Missing rain was stored as zero');
echo "work-log weather rain smoke checks passed\n";
