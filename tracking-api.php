<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
require_once __DIR__ . '/database.php';

function respond(int $status, array $body): never
{
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    header('Allow: GET');
    respond(405, ['error' => 'Only GET requests are supported.']);
}

$trackingCode = trim((string) ($_GET['code'] ?? ''));
if ($trackingCode === '' || !preg_match('/^[A-Za-z0-9-]{1,64}$/', $trackingCode)) {
    respond(400, ['error' => 'Enter a valid tracking code.']);
}

try {
    $pdo = cadence_db();

    $query = $pdo->prepare('SELECT * FROM shipments WHERE BINARY tracking_code = :tracking_code LIMIT 1');
    $query->execute(['tracking_code' => $trackingCode]);
    $shipment = $query->fetch();

    if (!$shipment) {
        respond(404, ['error' => 'No shipment was found for that tracking code.']);
    }

    $shipment['events'] = json_decode($shipment['events'], true, 512, JSON_THROW_ON_ERROR);
    respond(200, ['shipment' => $shipment]);
} catch (Throwable $error) {
    error_log($error->getMessage());
    respond(503, ['error' => 'Tracking is temporarily unavailable. Check the MAMP database connection.']);
}