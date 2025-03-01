<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

$redirect_count = filter_input(INPUT_GET, 'redirect_count', FILTER_SANITIZE_NUMBER_INT) ?? 0;
if ($redirect_count > 5) {
    session_destroy();
    header("Location: login.php?error=too_many_redirects");
    exit();
}

include 'config/Database.php';
include 'functions.php';

if (isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
    header("Location: index.php");
    exit();
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
    $password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);

    try {
        $database = new Database();
        $db = $database->getConnection();

        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['logged_in'] = true;
            $_SESSION['user'] = $user['username'];
            $_SESSION['role'] = $user['role'];
            error_log("Login successful. Session ID: " . session_id());
            $redirect = filter_input(INPUT_GET, 'redirect', FILTER_SANITIZE_URL) ?? 'index.php';
            header("Location: $redirect");
            exit();
        } else {
            $error = "Invalid username or password";
        }
    } catch (PDOException $e) {
        $error = "Login failed due to an error";
        error_log("Login error: " . $e->getMessage());
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Inventory System</title>
    <link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" as="style" onload="this.rel='stylesheet'">
    <link rel="stylesheet" href="styles.css" media="print" onload="this.media='all'">
</head>
<body>
    <div class="dashboard">
        <div class="container">
            <div class="card">
                <h2><i class="fas fa-sign-in-alt"></i> Login</h2>
                <?php if ($error): ?>
                    <div class="alert error" role="alert">
                        <i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($error) ?>
                    </div>
                <?php endif; ?>
                <?php if (isset($_GET['error']) && $_GET['error'] === 'too_many_redirects'): ?>
                    <div class="alert error" role="alert">
                        <i class="fas fa-exclamation-circle"></i> Too many redirects. Please clear your cookies and try again.
                    </div>
                <?php endif; ?>
                <form method="post" action="" novalidate>
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" name="username" required autofocus>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn primary"><i class="fas fa-sign-in-alt"></i> Login</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>