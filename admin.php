<?php
declare(strict_types=1);

session_name('cadence_admin');
$https = isset($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off';
session_set_cookie_params([
    'httponly' => true,
    'secure' => $https,
    'samesite' => 'Strict',
]);
session_start();
require_once __DIR__ . '/database.php';

function admin_escape(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function admin_is_local_request(): bool
{
    $address = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    return in_array($address, ['127.0.0.1', '::1', '::ffff:127.0.0.1'], true);
}

function admin_redirect(string $query = ''): never
{
    header('Location: admin.php' . $query, true, 303);
    exit;
}

function admin_valid_date(string $value): bool
{
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
    return $date !== false && $date->format('Y-m-d') === $value;
}

$pdo = cadence_db();
$adminCount = (int) $pdo->query('SELECT COUNT(*) FROM admin_users')->fetchColumn();
$setupAvailable = $adminCount === 0 && admin_is_local_request();
$isAuthenticated = isset($_SESSION['admin_id']);
$view = (string) ($_GET['view'] ?? 'overview');
if (!in_array($view, ['overview', 'invoices', 'invoice', 'shipments', 'shipment', 'payments'], true)) {
    $view = 'overview';
}
$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));
$csrfToken = (string) $_SESSION['csrf_token'];
$message = '';
$messageType = 'error';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedToken = (string) ($_POST['csrf_token'] ?? '');
    if (!hash_equals($csrfToken, $submittedToken)) {
        http_response_code(400);
        exit('Invalid request token. Reload the page and try again.');
    }

    $action = (string) ($_POST['action'] ?? '');
    try {
        if ($action === 'setup_admin') {
            if (!$setupAvailable || !admin_is_local_request()) {
                throw new RuntimeException('Initial setup is only available from this computer.');
            }
            $username = trim((string) ($_POST['username'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $confirm = (string) ($_POST['password_confirm'] ?? '');
            if (!preg_match('/^[A-Za-z0-9._-]{3,60}$/', $username)) {
                throw new InvalidArgumentException('Use a username with 3 to 60 letters, numbers, dots, underscores, or hyphens.');
            }
            if (strlen($password) < 12 || !hash_equals($password, $confirm)) {
                throw new InvalidArgumentException('Passwords must match and contain at least 12 characters.');
            }
            $insert = $pdo->prepare('INSERT INTO admin_users (username, password_hash) VALUES (:username, :password_hash)');
            $insert->execute(['username' => $username, 'password_hash' => password_hash($password, PASSWORD_DEFAULT)]);
            session_regenerate_id(true);
            $_SESSION['admin_id'] = (int) $pdo->lastInsertId();
            $_SESSION['admin_username'] = $username;
            admin_redirect('?welcome=1');
        }

        if ($action === 'login') {
            if (!$https && !admin_is_local_request()) {
                throw new RuntimeException('Admin sign-in requires HTTPS when accessed remotely.');
            }
            $now = time();
            if ((int) ($_SESSION['login_locked_until'] ?? 0) > $now) {
                throw new RuntimeException('Too many attempts. Wait a few minutes and try again.');
            }
            $username = trim((string) ($_POST['username'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $lookup = $pdo->prepare('SELECT id, username, password_hash FROM admin_users WHERE username = :username LIMIT 1');
            $lookup->execute(['username' => $username]);
            $user = $lookup->fetch();
            if (!$user || !password_verify($password, $user['password_hash'])) {
                $_SESSION['login_failures'] = (int) ($_SESSION['login_failures'] ?? 0) + 1;
                if ($_SESSION['login_failures'] >= 5) {
                    $_SESSION['login_locked_until'] = $now + 300;
                    $_SESSION['login_failures'] = 0;
                }
                throw new RuntimeException('Username or password is incorrect.');
            }
            session_regenerate_id(true);
            $_SESSION['admin_id'] = (int) $user['id'];
            $_SESSION['admin_username'] = $user['username'];
            unset($_SESSION['login_failures'], $_SESSION['login_locked_until']);
            admin_redirect();
        }

        if (!$isAuthenticated) {
            throw new RuntimeException('Sign in to continue.');
        }

        if ($action === 'logout') {
            $_SESSION = [];
            session_destroy();
            admin_redirect();
        }

        if ($action === 'save_invoice') {
            $id = filter_var($_POST['id'] ?? '0', FILTER_VALIDATE_INT);
            $invoiceNumber = trim((string) ($_POST['invoice_number'] ?? ''));
            $trackingCode = trim((string) ($_POST['tracking_code'] ?? ''));
            $customerName = trim((string) ($_POST['customer_name'] ?? ''));
            $customerEmail = trim((string) ($_POST['customer_email'] ?? ''));
            $description = trim((string) ($_POST['description'] ?? ''));
            $amount = filter_var($_POST['amount'] ?? null, FILTER_VALIDATE_FLOAT);
            $currency = strtoupper(trim((string) ($_POST['currency'] ?? 'USD')));
            $status = (string) ($_POST['status'] ?? 'draft');
            $issueDate = (string) ($_POST['issue_date'] ?? '');
            $dueDate = (string) ($_POST['due_date'] ?? '');
            $allowedStatuses = ['draft', 'sent', 'paid', 'overdue', 'cancelled'];

            if ($id === false || $id < 0 || !preg_match('/^[A-Za-z0-9_-]{1,64}$/', $invoiceNumber)) {
                throw new InvalidArgumentException('Enter a valid invoice number.');
            }
            if ($trackingCode !== '' && !preg_match('/^[A-Za-z0-9-]{1,64}$/', $trackingCode)) {
                throw new InvalidArgumentException('Enter a valid tracking code or leave it blank.');
            }
            if ($customerName === '' || strlen($customerName) > 150 || $description === '' || strlen($description) > 500) {
                throw new InvalidArgumentException('Customer and description are required and must fit their fields.');
            }
            if ($customerEmail !== '' && (!filter_var($customerEmail, FILTER_VALIDATE_EMAIL) || strlen($customerEmail) > 190)) {
                throw new InvalidArgumentException('Enter a valid customer email address.');
            }
            if ($amount === false || !is_finite((float) $amount) || $amount <= 0 || $amount > 9999999999) {
                throw new InvalidArgumentException('Enter an amount greater than zero.');
            }
            if (!preg_match('/^[A-Z]{3}$/', $currency) || !in_array($status, $allowedStatuses, true)) {
                throw new InvalidArgumentException('Choose a valid currency and invoice status.');
            }
            if (!admin_valid_date($issueDate) || !admin_valid_date($dueDate)) {
                throw new InvalidArgumentException('Enter valid issue and due dates.');
            }

            $values = [
                'invoice_number' => $invoiceNumber,
                'tracking_code' => $trackingCode !== '' ? $trackingCode : null,
                'customer_name' => $customerName,
                'customer_email' => $customerEmail !== '' ? $customerEmail : null,
                'description' => $description,
                'amount' => number_format((float) $amount, 2, '.', ''),
                'currency' => $currency,
                'status' => $status,
                'issue_date' => $issueDate,
                'due_date' => $dueDate,
            ];
            if ($id > 0) {
                $values['id'] = $id;
                $save = $pdo->prepare(
                    'UPDATE invoices SET invoice_number = :invoice_number, tracking_code = :tracking_code,
                     customer_name = :customer_name, customer_email = :customer_email, description = :description,
                     amount = :amount, currency = :currency, status = :status, issue_date = :issue_date,
                     due_date = :due_date WHERE id = :id'
                );
                $save->execute($values);
            } else {
                $save = $pdo->prepare(
                    'INSERT INTO invoices (invoice_number, tracking_code, customer_name, customer_email, description,
                     amount, currency, status, issue_date, due_date)
                     VALUES (:invoice_number, :tracking_code, :customer_name, :customer_email, :description,
                     :amount, :currency, :status, :issue_date, :due_date)'
                );
                $save->execute($values);
            }
            admin_redirect('?view=invoices&saved=invoice');
        }

        if ($action === 'delete_invoice') {
            $id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
            if ($id === false || $id < 1) {
                throw new InvalidArgumentException('Select a valid invoice.');
            }
            $delete = $pdo->prepare('DELETE FROM invoices WHERE id = :id');
            $delete->execute(['id' => $id]);
            admin_redirect('?view=invoices&saved=deleted');
        }

        if ($action === 'save_gateway') {
            $methods = [
                'crypto' => 1,
                'bank' => 2,
                'card' => 3,
            ];
            $upsert = $pdo->prepare(
                'INSERT INTO payment_gateway_settings
                 (method_key, provider, display_name, description, payment_details, checkout_url, enabled, sort_order)
                 VALUES (:method_key, :provider, :display_name, :description, :payment_details, :checkout_url, :enabled, :sort_order)
                 ON DUPLICATE KEY UPDATE provider = VALUES(provider), display_name = VALUES(display_name),
                 description = VALUES(description), payment_details = VALUES(payment_details),
                 checkout_url = VALUES(checkout_url), enabled = VALUES(enabled), sort_order = VALUES(sort_order)'
            );
            $gatewayInput = $_POST['gateway'] ?? [];
            foreach ($methods as $methodKey => $sortOrder) {
                $settings = is_array($gatewayInput[$methodKey] ?? null) ? $gatewayInput[$methodKey] : [];
                $provider = trim((string) ($settings['provider'] ?? ''));
                $displayName = trim((string) ($settings['display_name'] ?? ''));
                $description = trim((string) ($settings['description'] ?? ''));
                $paymentDetails = trim((string) ($settings['payment_details'] ?? ''));
                $checkoutUrl = trim((string) ($settings['checkout_url'] ?? ''));
                $enabled = isset($settings['enabled']) && (string) $settings['enabled'] === '1' ? 1 : 0;

                if ($provider === '' || $displayName === '' || strlen($provider) > 100 || strlen($displayName) > 100 || strlen($description) > 255) {
                    throw new InvalidArgumentException('Each payment method needs a valid provider and display name.');
                }
                if (strlen($paymentDetails) > 5000) {
                    throw new InvalidArgumentException('Payment instructions must be 5,000 characters or fewer.');
                }
                if ($checkoutUrl !== '') {
                    $url = filter_var($checkoutUrl, FILTER_VALIDATE_URL);
                    $scheme = strtolower((string) parse_url($checkoutUrl, PHP_URL_SCHEME));
                    if ($url === false || $scheme !== 'https' || strlen($checkoutUrl) > 500) {
                        throw new InvalidArgumentException('Hosted checkout URLs must be valid HTTPS URLs.');
                    }
                }
                if ($enabled && $paymentDetails === '' && $checkoutUrl === '') {
                    throw new InvalidArgumentException('Add payment instructions or a hosted checkout URL before enabling a method.');
                }
                $upsert->execute([
                    'method_key' => $methodKey,
                    'provider' => $provider,
                    'display_name' => $displayName,
                    'description' => $description,
                    'payment_details' => $paymentDetails,
                    'checkout_url' => $checkoutUrl !== '' ? $checkoutUrl : null,
                    'enabled' => $enabled,
                    'sort_order' => $sortOrder,
                ]);
            }
            admin_redirect('?view=payments&saved=gateway');
        }

        if ($action === 'save_shipment') {
            $trackingCode = trim((string) ($_POST['tracking_code'] ?? ''));
            $sender = trim((string) ($_POST['sender'] ?? ''));
            $receiver = trim((string) ($_POST['receiver'] ?? ''));
            $uniqueId = trim((string) ($_POST['unique_id'] ?? ''));
            if (!preg_match('/^[A-Za-z0-9-]{1,64}$/', $trackingCode)) {
                throw new InvalidArgumentException('Select a valid tracking code.');
            }
            if ($sender === '' || strlen($sender) > 150 || $receiver === '' || strlen($receiver) > 150) {
                throw new InvalidArgumentException('Sender and receiver are required and must be 150 characters or fewer.');
            }
            if (!preg_match('/^[A-Za-z0-9._-]{1,64}$/', $uniqueId)) {
                throw new InvalidArgumentException('Unique ID must be 1 to 64 letters, numbers, dots, underscores, or hyphens.');
            }
            $saveShipment = $pdo->prepare(
                'UPDATE shipments SET sender = :sender, receiver = :receiver, unique_id = :unique_id
                 WHERE BINARY tracking_code = :tracking_code'
            );
            $saveShipment->execute([
                'sender' => $sender,
                'receiver' => $receiver,
                'unique_id' => $uniqueId,
                'tracking_code' => $trackingCode,
            ]);
            if ($saveShipment->rowCount() === 0) {
                $exists = $pdo->prepare('SELECT 1 FROM shipments WHERE BINARY tracking_code = :tracking_code');
                $exists->execute(['tracking_code' => $trackingCode]);
                if (!$exists->fetchColumn()) {
                    throw new InvalidArgumentException('The selected shipment no longer exists.');
                }
            }
            admin_redirect('?view=shipments&saved=shipment');
        }

        throw new InvalidArgumentException('That action is not available.');
    } catch (Throwable $error) {
        error_log($error->getMessage());
        $message = $error instanceof InvalidArgumentException || $error instanceof RuntimeException
            ? $error->getMessage()
            : 'Could not save your changes. Check for duplicate invoice numbers and try again.';
    }
}

if (isset($_GET['welcome'])) {
    $message = 'Admin account created. You are signed in.';
    $messageType = 'success';
} elseif (isset($_GET['saved'])) {
    $savedLabels = ['invoice' => 'Invoice saved.', 'deleted' => 'Invoice deleted.', 'gateway' => 'Payment settings saved.', 'shipment' => 'Shipment details saved.'];
    $message = $savedLabels[(string) $_GET['saved']] ?? '';
    $messageType = 'success';
}

$editingInvoice = null;
$editingShipment = null;
$invoices = [];
$shipments = [];
$gatewaySettings = [];
if ($isAuthenticated) {
    $list = $pdo->query('SELECT * FROM invoices ORDER BY issue_date DESC, id DESC');
    $invoices = $list->fetchAll();
    $gatewayRows = $pdo->query('SELECT * FROM payment_gateway_settings ORDER BY sort_order')->fetchAll();
    foreach ($gatewayRows as $gatewayRow) {
        $gatewaySettings[$gatewayRow['method_key']] = $gatewayRow;
    }
    $shipments = $pdo->query(
        'SELECT tracking_code, unique_id, shipment_number, status, sender, receiver
         FROM shipments ORDER BY shipment_number'
    )->fetchAll();
    $shipmentCode = trim((string) ($_GET['code'] ?? ''));
    if ($shipmentCode === '' && $view === 'shipment' && $shipments) {
        $shipmentCode = $shipments[0]['tracking_code'];
    }
    if ($shipmentCode !== '') {
        $findShipment = $pdo->prepare('SELECT tracking_code, unique_id, shipment_number, sender, receiver FROM shipments WHERE BINARY tracking_code = :tracking_code');
        $findShipment->execute(['tracking_code' => $shipmentCode]);
        $editingShipment = $findShipment->fetch() ?: null;
    }
    $editId = filter_var($_GET['edit'] ?? null, FILTER_VALIDATE_INT);
    if ($editId !== false && $editId !== null && $editId > 0) {
        $find = $pdo->prepare('SELECT * FROM invoices WHERE id = :id');
        $find->execute(['id' => $editId]);
        $editingInvoice = $find->fetch() ?: null;
    }
}

$today = date('Y-m-d');
$defaultDue = date('Y-m-d', strtotime('+30 days'));
$invoiceForm = $editingInvoice ?: [
    'id' => 0,
    'invoice_number' => 'INV-' . date('Ymd') . '-' . random_int(100, 999),
    'tracking_code' => '',
    'customer_name' => '',
    'customer_email' => '',
    'description' => '',
    'amount' => '',
    'currency' => 'USD',
    'status' => 'draft',
    'issue_date' => $today,
    'due_date' => $defaultDue,
];
$shipmentForm = $editingShipment ?: [
    'tracking_code' => '',
    'unique_id' => '',
    'shipment_number' => '',
    'sender' => '',
    'receiver' => '',
];
$gatewayDefaults = [
    'crypto' => ['provider' => 'Crypto wallet', 'display_name' => 'Crypto', 'description' => 'Bitcoin, Ethereum, USDT', 'payment_details' => '', 'checkout_url' => '', 'enabled' => 0],
    'bank' => ['provider' => 'Bank transfer', 'display_name' => 'Bank transfer', 'description' => 'Direct bank payment', 'payment_details' => '', 'checkout_url' => '', 'enabled' => 0],
    'card' => ['provider' => 'Hosted card checkout', 'display_name' => 'Card', 'description' => 'Visa, Mastercard, American Express', 'payment_details' => '', 'checkout_url' => '', 'enabled' => 0],
];
$gatewaySettings = array_replace_recursive($gatewayDefaults, $gatewaySettings);
$openInvoiceCount = 0;
$outstandingAmount = 0.0;
foreach ($invoices as $invoice) {
    if (!in_array($invoice['status'], ['paid', 'cancelled'], true)) {
        $openInvoiceCount++;
        if ($invoice['currency'] === 'USD') {
            $outstandingAmount += (float) $invoice['amount'];
        }
    }
}
$enabledMethodCount = 0;
foreach ($gatewaySettings as $method) {
    if ((int) $method['enabled'] === 1) {
        $enabledMethodCount++;
    }
}
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Movere | Admin</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{color-scheme:light;--ink:#202624;--muted:#75807b;--line:#e1e7e3;--paper:#fff;--wash:#f3f6f3;--green:#176d52;--green-pale:#e7f2ec;--red:#a63832;--red-pale:#fbefed;--gold:#e4c397}
*{box-sizing:border-box}body{margin:0;background:var(--wash);color:var(--ink);font:14px 'DM Sans',sans-serif}button,input,textarea,select{font:inherit}a{color:inherit}.topbar{height:68px;display:flex;align-items:center;justify-content:space-between;padding:0 28px;background:#fff;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:11px;text-decoration:none;font:700 19px Manrope,sans-serif}.brand-mark{display:grid;place-items:center;width:34px;height:34px;border-radius:10px;background:var(--gold);color:#fff}.topbar-right{display:flex;align-items:center;gap:18px;color:var(--muted);font-size:12px}.topbar-right form{margin:0}.shell{max-width:1220px;margin:0 auto;padding:34px 26px 56px}.page-head{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;margin-bottom:25px}.eyebrow{margin:0 0 7px;color:var(--green);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}.page-head h1{margin:0;font:600 30px Manrope,sans-serif}.page-head p:last-child{margin:8px 0 0;color:var(--muted)}.columns{display:grid;grid-template-columns:minmax(300px,.8fr) minmax(0,1.4fr);gap:22px;align-items:start}.section{min-width:0;padding:22px 0;border-top:1px solid var(--line)}.section h2{margin:0 0 5px;font:600 18px Manrope,sans-serif}.section-intro{margin:0 0 18px;color:var(--muted);font-size:12px;line-height:1.55}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:13px}.field{display:grid;gap:6px;min-width:0}.field.full{grid-column:1/-1}.field label{font-size:11px;font-weight:700;color:#525d58}.field input,.field select,.field textarea{width:100%;min-height:40px;padding:9px 10px;border:1px solid #d5ded8;border-radius:5px;background:#fff;color:var(--ink);outline:none}.field textarea{min-height:85px;resize:vertical;line-height:1.5}.field input:focus,.field select:focus,.field textarea:focus{border-color:var(--green);box-shadow:0 0 0 2px #176d5218}.button{min-height:38px;display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:0 13px;border:1px solid var(--green);border-radius:5px;background:var(--green);color:white;text-decoration:none;font-size:12px;font-weight:700;cursor:pointer}.button:hover{background:#115940}.button.secondary{border-color:#ccd6cf;background:#fff;color:#35423b}.button.danger{border-color:#ead3d0;background:#fff;color:var(--red)}.button.small{min-height:30px;padding:0 9px;font-size:11px}.actions{display:flex;align-items:center;gap:8px;margin-top:16px}.notice{margin:0 0 20px;padding:12px 14px;border:1px solid #d8e8dc;border-radius:5px;background:var(--green-pale);color:var(--green);font-size:13px}.notice.error{border-color:#f0d7d4;background:var(--red-pale);color:var(--red)}.table-wrap{overflow:auto;border:1px solid var(--line);background:#fff}.invoice-table{width:100%;border-collapse:collapse;white-space:nowrap;text-align:left}.invoice-table th,.invoice-table td{padding:11px 12px;border-bottom:1px solid #edf0ed;font-size:12px}.invoice-table th{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.04em;background:#fafbfa}.invoice-table tr:last-child td{border-bottom:0}.invoice-id{font-weight:700}.subline{display:block;margin-top:4px;color:var(--muted);font-size:11px}.status{display:inline-flex;padding:4px 7px;border-radius:3px;background:#eef1ef;color:#53615a;font-size:10px;font-weight:700;text-transform:capitalize}.status.paid{background:var(--green-pale);color:var(--green)}.row-actions{display:flex;align-items:center;gap:6px}.row-actions form{margin:0}.gateway-list{display:grid;gap:18px}.gateway-method{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:16px 0;border-top:1px solid var(--line)}.gateway-method h3{grid-column:1/-1;margin:0;font:600 14px Manrope,sans-serif}.toggle{display:flex;align-items:center;gap:8px;min-height:40px;color:#46524c;font-size:12px;font-weight:600}.toggle input{width:16px;height:16px;accent-color:var(--green)}.security-note{margin-top:15px;padding:11px 12px;border-left:3px solid var(--gold);background:#f8f6f2;color:#59625d;font-size:11px;line-height:1.5}.empty{padding:22px;color:var(--muted);text-align:center}.auth-wrap{max-width:440px;margin:8vh auto;padding:26px;background:#fff;border:1px solid var(--line)}.auth-wrap h1{margin:0 0 7px;font:600 24px Manrope,sans-serif}.auth-wrap>p{margin:0 0 20px;color:var(--muted);line-height:1.5}.auth-wrap .field+.field{margin-top:14px}.auth-wrap .button{width:100%;margin-top:18px}.auth-brand{margin-bottom:26px}.legal{margin-top:18px;color:var(--muted);font-size:11px;line-height:1.5}
.admin-layout{display:grid;grid-template-columns:220px minmax(0,1fr);max-width:1480px;min-height:calc(100vh - 68px);margin:0 auto}.sidebar{padding:25px 12px 30px 18px;background:#fff;border-right:1px solid var(--line)}.sidebar-label{margin:0 0 11px 10px;color:var(--muted);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}.sidebar-nav{display:grid;gap:4px}.sidebar-link{display:flex;align-items:center;gap:10px;min-height:40px;padding:0 10px;border-radius:4px;color:#59645e;text-decoration:none;font-size:12px;font-weight:600}.sidebar-link:hover{background:#f4f7f4;color:var(--ink)}.sidebar-link.is-active{background:var(--green-pale);color:var(--green)}.sidebar-icon{width:18px;text-align:center;font-size:15px}.sidebar-count{margin-left:auto;color:var(--muted);font-size:10px}.shell{max-width:none;min-width:0;margin:0;padding:34px clamp(20px,4vw,48px) 56px}.columns.single{display:block}.overview-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:8px 0 26px}.stat{padding:17px 0;border-top:2px solid var(--green)}.stat span{display:block;color:var(--muted);font-size:11px}.stat strong{display:block;margin-top:8px;font:600 26px Manrope,sans-serif}.quick-links{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;max-width:760px}.quick-link{display:flex;justify-content:space-between;align-items:center;min-height:68px;padding:14px;border:1px solid var(--line);background:#fff;text-decoration:none;font-weight:600}.quick-link span{color:var(--green)}
@media(max-width:850px){.admin-layout{grid-template-columns:180px minmax(0,1fr)}.columns{grid-template-columns:1fr}.shell{padding:26px 18px 42px}.page-head{align-items:flex-start;flex-direction:column}.topbar{padding:0 18px}}
@media(max-width:650px){.admin-layout{grid-template-columns:1fr}.sidebar{padding:8px 12px;border-right:0;border-bottom:1px solid var(--line)}.sidebar-label{display:none}.sidebar-nav{display:flex;overflow-x:auto}.sidebar-link{flex:none;padding:0 9px}.sidebar-count{display:none}.shell{padding:24px 18px 42px}.overview-stats{grid-template-columns:1fr 1fr}.quick-links{grid-template-columns:1fr}}
@media(max-width:520px){.topbar-right>span{display:none}.shell{padding:22px 14px 36px}.form-grid,.gateway-method{grid-template-columns:1fr}.gateway-method h3,.field.full{grid-column:auto}.page-head h1{font-size:26px}.topbar{height:60px}.row-actions{flex-direction:column;align-items:flex-start}}
</style>
</head>
<body>
<header class="topbar">
  <a class="brand" href="index.html"><span class="brand-mark" aria-hidden="true">M</span>Movere <span style="color:var(--muted);font-size:12px;font-weight:500">Admin</span></a>
  <?php if ($isAuthenticated): ?>
  <div class="topbar-right"><span><?= admin_escape($_SESSION['admin_username'] ?? 'Admin') ?></span><form method="post"><input type="hidden" name="csrf_token" value="<?= admin_escape($csrfToken) ?>"><input type="hidden" name="action" value="logout"><button class="button secondary small" type="submit">Sign out</button></form></div>
  <?php endif; ?>
</header>
<?php if (!$isAuthenticated): ?>
<main class="auth-wrap">
  <a class="brand auth-brand" href="index.html"><span class="brand-mark" aria-hidden="true">M</span>Movere Admin</a>
  <?php if ($message !== ''): ?><p class="notice error" role="alert"><?= admin_escape($message) ?></p><?php endif; ?>
  <?php if ($setupAvailable): ?>
  <h1>Create admin account</h1><p>Choose the first administrator login. Initial setup is available only from this computer.</p>
  <form method="post" autocomplete="off">
    <input type="hidden" name="csrf_token" value="<?= admin_escape($csrfToken) ?>"><input type="hidden" name="action" value="setup_admin">
    <div class="field"><label for="setup-username">Username</label><input id="setup-username" name="username" minlength="3" maxlength="60" required autocomplete="username"></div>
    <div class="field"><label for="setup-password">Password (12 characters minimum)</label><input id="setup-password" type="password" name="password" minlength="12" required autocomplete="new-password"></div>
    <div class="field"><label for="setup-confirm">Confirm password</label><input id="setup-confirm" type="password" name="password_confirm" minlength="12" required autocomplete="new-password"></div>
    <button class="button" type="submit">Create admin account</button>
  </form>
  <?php else: ?>
  <h1>Admin sign in</h1><p>Sign in to manage invoices and payment methods.</p>
  <form method="post" autocomplete="on">
    <input type="hidden" name="csrf_token" value="<?= admin_escape($csrfToken) ?>"><input type="hidden" name="action" value="login">
    <div class="field"><label for="login-username">Username</label><input id="login-username" name="username" required autocomplete="username"></div>
    <div class="field"><label for="login-password">Password</label><input id="login-password" type="password" name="password" required autocomplete="current-password"></div>
    <button class="button" type="submit">Sign in</button>
  </form>
  <?php endif; ?>
  <p class="legal">Admin access uses a separate session. Keep payment processor API secrets in server environment settings, not in this dashboard.</p>
</main>
<?php else: ?>
<main class="admin-layout">
    <aside class="sidebar" aria-label="Admin navigation">
        <p class="sidebar-label">Workspace</p>
        <nav class="sidebar-nav">
            <a class="sidebar-link <?= $view === 'overview' ? 'is-active' : '' ?>" href="admin.php?view=overview" <?= $view === 'overview' ? 'aria-current="page"' : '' ?>><span class="sidebar-icon" aria-hidden="true">⌂</span>Overview</a>
            <a class="sidebar-link <?= $view === 'invoices' ? 'is-active' : '' ?>" href="admin.php?view=invoices" <?= $view === 'invoices' ? 'aria-current="page"' : '' ?>><span class="sidebar-icon" aria-hidden="true">▤</span>Invoices<span class="sidebar-count"><?= count($invoices) ?></span></a>
            <a class="sidebar-link <?= $view === 'invoice' ? 'is-active' : '' ?>" href="admin.php?view=invoice" <?= $view === 'invoice' ? 'aria-current="page"' : '' ?>><span class="sidebar-icon" aria-hidden="true">＋</span>New invoice</a>
            <a class="sidebar-link <?= in_array($view, ['shipments', 'shipment'], true) ? 'is-active' : '' ?>" href="admin.php?view=shipments" <?= in_array($view, ['shipments', 'shipment'], true) ? 'aria-current="page"' : '' ?>><span class="sidebar-icon" aria-hidden="true">▣</span>Shipments<span class="sidebar-count"><?= count($shipments) ?></span></a>
            <a class="sidebar-link <?= $view === 'payments' ? 'is-active' : '' ?>" href="admin.php?view=payments" <?= $view === 'payments' ? 'aria-current="page"' : '' ?>><span class="sidebar-icon" aria-hidden="true">↗</span>Payment gateway<span class="sidebar-count"><?= $enabledMethodCount ?> active</span></a>
        </nav>
    </aside>
    <div class="shell">
    <div class="page-head"><div><p class="eyebrow">Operations</p><h1><?= $view === 'overview' ? 'Overview' : ($view === 'invoices' ? 'Invoices' : ($view === 'invoice' ? ($editingInvoice ? 'Edit invoice' : 'New invoice') : ($view === 'shipments' ? 'Shipments' : ($view === 'shipment' ? 'Edit shipment' : 'Payment gateway')))) ?></h1><p><?= $view === 'payments' ? 'Manage customer-facing payment instructions and checkout links.' : (in_array($view, ['shipment', 'shipments'], true) ? 'Edit sender, receiver, and shipment identifiers.' : ($view === 'invoice' ? 'Add or update invoice information.' : 'Monitor invoices and payment configuration.')) ?></p></div><?php if ($view === 'payments'): ?><a class="button secondary" href="payment.html">View checkout</a><?php elseif ($view === 'invoices'): ?><a class="button" href="admin.php?view=invoice">New invoice</a><?php endif; ?></div>
  <?php if ($message !== ''): ?><p class="notice <?= $messageType === 'error' ? 'error' : '' ?>" role="status"><?= admin_escape($message) ?></p><?php endif; ?>
    <?php if ($view === 'overview'): ?>
    <div class="overview-stats">
        <div class="stat"><span>Total invoices</span><strong><?= count($invoices) ?></strong></div>
        <div class="stat"><span>Open USD balance</span><strong>USD <?= number_format($outstandingAmount, 2) ?></strong></div>
        <div class="stat"><span>Enabled payment methods</span><strong><?= $enabledMethodCount ?></strong></div>
    </div>
    <div class="quick-links"><a class="quick-link" href="admin.php?view=invoices">Manage invoices <span>→</span></a><a class="quick-link" href="admin.php?view=shipments">Shipment details <span>→</span></a><a class="quick-link" href="admin.php?view=payments">Payment gateway <span>→</span></a></div>
    <?php elseif ($view === 'invoice'): ?>
    <div class="columns single">
    <?php endif; ?>
    <?php if ($view === 'invoice'): ?>
    <section class="section" id="invoice-editor">
      <h2><?= $editingInvoice ? 'Edit invoice' : 'New invoice' ?></h2>
      <p class="section-intro">Create or update an invoice record. Invoice numbers must be unique.</p>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?= admin_escape($csrfToken) ?>"><input type="hidden" name="action" value="save_invoice"><input type="hidden" name="id" value="<?= (int) $invoiceForm['id'] ?>">
        <div class="form-grid">
          <div class="field"><label for="invoice-number">Invoice number</label><input id="invoice-number" name="invoice_number" maxlength="64" required value="<?= admin_escape($invoiceForm['invoice_number']) ?>"></div>
          <div class="field"><label for="invoice-tracking">Tracking code</label><input id="invoice-tracking" name="tracking_code" maxlength="64" value="<?= admin_escape($invoiceForm['tracking_code']) ?>"></div>
          <div class="field"><label for="customer-name">Customer</label><input id="customer-name" name="customer_name" maxlength="150" required value="<?= admin_escape($invoiceForm['customer_name']) ?>"></div>
          <div class="field"><label for="customer-email">Customer email</label><input id="customer-email" type="email" name="customer_email" maxlength="190" value="<?= admin_escape($invoiceForm['customer_email']) ?>"></div>
          <div class="field full"><label for="invoice-description">Description</label><input id="invoice-description" name="description" maxlength="500" required value="<?= admin_escape($invoiceForm['description']) ?>"></div>
          <div class="field"><label for="invoice-amount">Amount</label><input id="invoice-amount" type="number" name="amount" min="0.01" max="9999999999" step="0.01" required value="<?= admin_escape($invoiceForm['amount']) ?>"></div>
          <div class="field"><label for="invoice-currency">Currency</label><input id="invoice-currency" name="currency" maxlength="3" pattern="[A-Za-z]{3}" required value="<?= admin_escape($invoiceForm['currency']) ?>"></div>
          <div class="field"><label for="invoice-status">Status</label><select id="invoice-status" name="status"><?php foreach (['draft','sent','paid','overdue','cancelled'] as $invoiceStatus): ?><option value="<?= $invoiceStatus ?>" <?= $invoiceForm['status'] === $invoiceStatus ? 'selected' : '' ?>><?= ucfirst($invoiceStatus) ?></option><?php endforeach; ?></select></div>
          <div class="field"><label for="issue-date">Issue date</label><input id="issue-date" type="date" name="issue_date" required value="<?= admin_escape($invoiceForm['issue_date']) ?>"></div>
          <div class="field"><label for="due-date">Due date</label><input id="due-date" type="date" name="due_date" required value="<?= admin_escape($invoiceForm['due_date']) ?>"></div>
        </div>
        <div class="actions"><button class="button" type="submit"><?= $editingInvoice ? 'Save invoice' : 'Create invoice' ?></button><?php if ($editingInvoice): ?><a class="button secondary" href="admin.php?view=invoices">Cancel</a><?php endif; ?></div>
      </form>
    </section>
    </div>
    <?php elseif ($view === 'invoices'): ?>
    <section class="section">
      <h2>Invoices <span style="color:var(--muted);font-size:13px">(<?= count($invoices) ?>)</span></h2>
      <p class="section-intro">Review invoice status, amount, and due date.</p>
      <?php if ($invoices): ?>
      <div class="table-wrap"><table class="invoice-table"><thead><tr><th>Invoice</th><th>Customer</th><th>Amount</th><th>Status</th><th>Due</th><th>Actions</th></tr></thead><tbody>
      <?php foreach ($invoices as $invoice): ?><tr>
        <td><span class="invoice-id"><?= admin_escape($invoice['invoice_number']) ?></span><?php if ($invoice['tracking_code']): ?><span class="subline"><?= admin_escape($invoice['tracking_code']) ?></span><?php endif; ?></td>
        <td><?= admin_escape($invoice['customer_name']) ?><?php if ($invoice['customer_email']): ?><span class="subline"><?= admin_escape($invoice['customer_email']) ?></span><?php endif; ?></td>
        <td><?= admin_escape($invoice['currency']) ?> <?= number_format((float) $invoice['amount'], 2) ?></td>
        <td><span class="status <?= $invoice['status'] === 'paid' ? 'paid' : '' ?>"><?= admin_escape($invoice['status']) ?></span></td>
        <td><?= admin_escape($invoice['due_date']) ?></td>
        <td><div class="row-actions"><a class="button secondary small" href="admin.php?view=invoice&edit=<?= (int) $invoice['id'] ?>">Edit</a><form method="post" onsubmit="return confirm('Delete this invoice?')"><input type="hidden" name="csrf_token" value="<?= admin_escape($csrfToken) ?>"><input type="hidden" name="action" value="delete_invoice"><input type="hidden" name="id" value="<?= (int) $invoice['id'] ?>"><button class="button danger small" type="submit">Delete</button></form></div></td>
      </tr><?php endforeach; ?>
      </tbody></table></div>
      <?php else: ?><div class="table-wrap empty">No invoices yet.</div><?php endif; ?>
    </section>
        <?php elseif ($view === 'shipments'): ?>
        <section class="section">
            <h2>Shipments <span style="color:var(--muted);font-size:13px">(<?= count($shipments) ?>)</span></h2>
            <p class="section-intro">Update the sender, receiver, or unique parcel identifier for a shipment.</p>
            <?php if ($shipments): ?>
            <div class="table-wrap"><table class="invoice-table"><thead><tr><th>Tracking code</th><th>Shipment</th><th>Sender</th><th>Receiver</th><th>Unique ID</th><th>Status</th><th>Action</th></tr></thead><tbody>
            <?php foreach ($shipments as $shipment): ?><tr>
                <td><?= admin_escape($shipment['tracking_code']) ?></td>
                <td><?= admin_escape($shipment['shipment_number']) ?></td>
                <td><?= admin_escape($shipment['sender']) ?></td>
                <td><?= admin_escape($shipment['receiver']) ?></td>
                <td><?= admin_escape($shipment['unique_id']) ?></td>
                <td><?= admin_escape($shipment['status']) ?></td>
                <td><a class="button secondary small" href="admin.php?view=shipment&amp;code=<?= rawurlencode($shipment['tracking_code']) ?>">Edit</a></td>
            </tr><?php endforeach; ?>
            </tbody></table></div>
            <?php else: ?><div class="table-wrap empty">No shipments yet.</div><?php endif; ?>
        </section>
        <?php elseif ($view === 'shipment'): ?>
        <section class="section">
            <h2>Shipment details</h2>
            <p class="section-intro">These values appear in the parcel section of the tracking page.</p>
            <?php if ($editingShipment): ?>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= admin_escape($csrfToken) ?>"><input type="hidden" name="action" value="save_shipment"><input type="hidden" name="tracking_code" value="<?= admin_escape($shipmentForm['tracking_code']) ?>">
                <div class="form-grid">
                    <div class="field"><label for="shipment-code">Tracking code</label><input id="shipment-code" readonly value="<?= admin_escape($shipmentForm['tracking_code']) ?>"></div>
                    <div class="field"><label for="shipment-number">Shipment number</label><input id="shipment-number" readonly value="<?= admin_escape($shipmentForm['shipment_number']) ?>"></div>
                    <div class="field"><label for="shipment-sender">Sender</label><input id="shipment-sender" name="sender" maxlength="150" required value="<?= admin_escape($shipmentForm['sender']) ?>"></div>
                    <div class="field"><label for="shipment-receiver">Receiver</label><input id="shipment-receiver" name="receiver" maxlength="150" required value="<?= admin_escape($shipmentForm['receiver']) ?>"></div>
                      <div class="field"><label for="shipment-unique-id">Unique ID</label><input id="shipment-unique-id" name="unique_id" maxlength="64" pattern="[A-Za-z0-9._\-]{1,64}" required value="<?= admin_escape($shipmentForm['unique_id']) ?>"></div>
                </div>
                <div class="actions"><button class="button" type="submit">Save shipment details</button><a class="button secondary" href="admin.php?view=shipments">Cancel</a></div>
            </form>
            <?php else: ?><div class="table-wrap empty">Shipment not found. Return to the shipments list and choose a record.</div><?php endif; ?>
        </section>
        <?php elseif ($view === 'payments'): ?>
    <section class="section" id="gateway-settings">
    <h2>Payment methods</h2>
    <p class="section-intro">Only enabled methods appear on checkout. Public instructions and hosted checkout URLs are shown to customers.</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?= admin_escape($csrfToken) ?>"><input type="hidden" name="action" value="save_gateway">
      <div class="gateway-list">
      <?php foreach (['crypto' => 'Crypto', 'bank' => 'Bank transfer', 'card' => 'Card'] as $methodKey => $methodTitle): $method = $gatewaySettings[$methodKey]; ?>
        <div class="gateway-method">
          <h3><?= admin_escape($methodTitle) ?></h3>
          <div class="field"><label for="<?= $methodKey ?>-provider">Provider</label><input id="<?= $methodKey ?>-provider" name="gateway[<?= $methodKey ?>][provider]" maxlength="100" required value="<?= admin_escape($method['provider']) ?>"></div>
          <div class="field"><label for="<?= $methodKey ?>-name">Customer-facing name</label><input id="<?= $methodKey ?>-name" name="gateway[<?= $methodKey ?>][display_name]" maxlength="100" required value="<?= admin_escape($method['display_name']) ?>"></div>
          <div class="field"><label for="<?= $methodKey ?>-description">Description</label><input id="<?= $methodKey ?>-description" name="gateway[<?= $methodKey ?>][description]" maxlength="255" value="<?= admin_escape($method['description']) ?>"></div>
          <div class="field"><label for="<?= $methodKey ?>-url">Hosted checkout URL (HTTPS)</label><input id="<?= $methodKey ?>-url" type="url" name="gateway[<?= $methodKey ?>][checkout_url]" maxlength="500" placeholder="https://" value="<?= admin_escape($method['checkout_url']) ?>"></div>
          <div class="field full"><label for="<?= $methodKey ?>-details">Payment instructions or account details</label><textarea id="<?= $methodKey ?>-details" name="gateway[<?= $methodKey ?>][payment_details]" maxlength="5000"><?= admin_escape($method['payment_details']) ?></textarea></div>
          <label class="toggle"><input type="checkbox" name="gateway[<?= $methodKey ?>][enabled]" value="1" <?= (int) $method['enabled'] === 1 ? 'checked' : '' ?>>Enabled on checkout</label>
        </div>
      <?php endforeach; ?>
      </div>
      <p class="security-note">Never enter gateway API secrets or private keys here. Store processor credentials in server environment settings; this page saves customer-facing payment information only.</p>
      <div class="actions"><button class="button" type="submit">Save payment settings</button></div>
    </form>
  </section>
    <?php endif; ?>
    </div>
</main>
<?php endif; ?>
</body>
</html>
