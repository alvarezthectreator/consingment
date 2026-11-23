<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
require_once __DIR__ . '/database.php';

try {
    $query = cadence_db()->query(
        'SELECT method_key, provider, display_name, description, payment_details, checkout_url
         FROM payment_gateway_settings
         WHERE enabled = 1
         ORDER BY sort_order, display_name'
    );
    echo json_encode(
        ['methods' => $query->fetchAll()],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );
} catch (Throwable $error) {
    error_log($error->getMessage());
    http_response_code(503);
    echo json_encode(['error' => 'Payment options are temporarily unavailable.']);
}
