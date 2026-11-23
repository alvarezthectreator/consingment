<?php
declare(strict_types=1);

function cadence_db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $host = getenv('MAMP_DB_HOST') ?: '127.0.0.1';
    $port = getenv('MAMP_DB_PORT') ?: '8889';
    $name = getenv('MAMP_DB_NAME') ?: 'cadence_tracking';
    $user = getenv('MAMP_DB_USER') ?: 'root';
    $password = getenv('MAMP_DB_PASSWORD') ?: 'root';

    $pdo = new PDO(
        "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4",
        $user,
        $password,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );

    return $pdo;
}
