<?php
session_start();
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("Location: login.php");
    exit();
}

if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

include 'config/Database.php';
include 'functions.php';

try {
    $database = new Database();
    $db = $database->getConnection();

    $items_per_page = 10;
    $page = max(1, (int)filter_input(INPUT_GET, 'page', FILTER_SANITIZE_NUMBER_INT) ?? 1);
    $search = filter_input(INPUT_GET, 'search', FILTER_SANITIZE_SPECIAL_CHARS) ?? '';
    $sort = filter_input(INPUT_GET, 'sort', FILTER_SANITIZE_SPECIAL_CHARS) ?? 'updated_at';
    $sort = in_array($sort, ['name', 'quantity', 'price', 'category', 'updated_at']) ? $sort : 'updated_at';
    $order = strtoupper(filter_input(INPUT_GET, 'order', FILTER_SANITIZE_SPECIAL_CHARS) ?? 'DESC');
    $order = in_array($order, ['ASC', 'DESC']) ? $order : 'DESC';

    $stmt = $db->prepare("SELECT DISTINCT i.id, i.name, i.quantity, i.price, i.low_stock_threshold, i.reorder_threshold, i.updated_at FROM items i WHERE name LIKE ? ORDER BY i.$sort $order LIMIT ? OFFSET ?");
    $stmt->execute(["%$search%", $items_per_page, ($page - 1) * $items_per_page]);
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $countStmt = $db->prepare("SELECT COUNT(DISTINCT id) AS total FROM items WHERE name LIKE ?");
    $countStmt->execute(["%$search%"]);
    $total = $countStmt->fetchColumn();
    $total_pages = ceil($total / $items_per_page);

    $summaryStmt = $db->prepare("SELECT 
        COUNT(*) AS total, 
        SUM(CASE WHEN quantity <= low_stock_threshold THEN 1 ELSE 0 END) AS low_stock, 
        SUM(CASE WHEN quantity <= reorder_threshold THEN 1 ELSE 0 END) AS reorder_needed, 
        SUM(COALESCE(quantity, 0) * COALESCE(price, 0)) AS total_value 
        FROM items");
    $summaryStmt->execute();
    $summary = $summaryStmt->fetch(PDO::FETCH_ASSOC) ?: ['total' => 0, 'low_stock' => 0, 'reorder_needed' => 0, 'total_value' => 0.00];

    $notifyStmt = $db->prepare("SELECT id, message, created_at FROM notifications WHERE user = ? ORDER BY created_at DESC LIMIT 10");
    $notifyStmt->execute([$_SESSION['user']]);
    $notifications = $notifyStmt->fetchAll(PDO::FETCH_ASSOC);

    $logs = [];
    if ($_SESSION['role'] === 'admin') {
        $logStmt = $db->prepare("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 10");
        $logStmt->execute();
        $logs = $logStmt->fetchAll(PDO::FETCH_ASSOC);
    }

} catch (Exception $e) {
    $_SESSION['error'] = "Database connection failed: " . $e->getMessage();
    error_log("Database error: " . $e->getMessage());
    $items = [];
    $summary = ['total' => 0, 'low_stock' => 0, 'reorder_needed' => 0, 'total_value' => 0.00];
    $notifications = [];
    $logs = [];
}

$sessionAlerts = [
    'inventory-items' => ['message' => $_SESSION['message'] ?? '', 'error' => $_SESSION['error'] ?? ''],
    'add-edit-form' => ['message' => $_SESSION['item_message'] ?? '', 'error' => $_SESSION['item_error'] ?? '']
];
unset($_SESSION['message'], $_SESSION['error'], $_SESSION['item_message'], $_SESSION['item_error']);

function displayAlerts($sessionKey) {
    $html = '';
    if (isset($_SESSION[$sessionKey . '_error'])) {
        $html .= "<div class=\"alert error\" role=\"alert\"><i class=\"fas fa-exclamation-circle\"></i> " . htmlspecialchars($_SESSION[$sessionKey . '_error']) . "</div>";
        unset($_SESSION[$sessionKey . '_error']);
    }
    if (isset($_SESSION[$sessionKey . '_message'])) {
        $html .= "<div class=\"alert success\" role=\"alert\"><i class=\"fas fa-check-circle\"></i> " . htmlspecialchars($_SESSION[$sessionKey . '_message']) . "</div>";
        unset($_SESSION[$sessionKey . '_message']);
    }
    return $html ? "<div class=\"alert-container\" id=\"alert-$sessionKey\">$html</div>" : '';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Inventory System</title>
    <meta name="csrf-token" content="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
    <link rel="preload" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" as="style" onload="this.rel='stylesheet'">
    <link rel="stylesheet" href="styles.css" media="print" onload="this.media='all'">
    <style>
        /* Refined Inline Styles */
        :root {
            --primary: #007bff;
            --secondary: #6c757d;
            --success: #28a745;
            --danger: #dc3545;
            --light: #f8f9fa;
            --dark: #343a40;
        }
        body {
            background: var(--light);
            font-family: 'Segoe UI', Arial, sans-serif;
            color: var(--dark);
            margin: 0;
            padding: 0;
        }
        .navbar {
            background: var(--primary); /* Solid color, no gradient */
            position: fixed;
            top: 0;
            width: 100%;
            z-index: 1000;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            padding: 0;
        }
        .navbar-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.5rem 1rem; /* Reduced padding for smaller height */
        }
        .header-logo {
            height: 50px; /* Reduced from 80px to 50px */
            width: auto;
            transition: transform 0.3s;
        }
        .header-logo:hover {
            transform: scale(1.05);
        }
        .header-logo-placeholder {
            width: 50px; /* Reduced from 80px to 50px */
            height: 50px; /* Reduced from 80px to 50px */
            background: #e9ecef;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
            font-size: 1.5rem; /* Adjusted for smaller size */
            transition: background 0.3s;
        }
        .header-logo-placeholder:hover {
            background: #dee2e6;
        }
        .navbar h2 {
            font-size: 1.75rem; /* Reduced from 2.5rem to 1.75rem */
            color: white;
            margin: 0;
            font-weight: 600;
            flex-grow: 1;
            text-align: center;
            letter-spacing: 1px;
        }
        .nav-list {
            display: flex;
            justify-content: center;
            gap: 0.5rem;
            list-style: none;
            padding: 0.3rem 1rem; /* Reduced padding for smaller height */
            margin: 0 auto;
            max-width: 1200px;
            background: rgba(0, 0, 0, 0.05);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        .nav-list li a {
            color: white;
            text-decoration: none;
            padding: 0.4rem 1rem; /* Reduced padding for smaller links */
            border-radius: 6px;
            font-size: 0.9rem; /* Slightly smaller font */
            font-weight: 500;
            transition: background 0.3s, color 0.3s;
            display: block;
        }
        .nav-list li a:hover {
            background: rgba(255, 255, 255, 0.15);
            color: #f8f9fa;
        }
        .nav-list li a.active {
            background: rgba(255, 255, 255, 0.25);
        }
        .container {
            max-width: 1200px;
            margin: 90px auto 0; /* Reduced from 120px to 90px to match smaller navbar */
            padding: 1rem;
        }
        .card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            transition: box-shadow 0.3s;
        }
        .card:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }
        .card h2 {
            font-size: 1.5rem;
            color: var(--dark);
            margin-bottom: 1rem;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
        }
        .modal-content {
            background: white;
            margin: 5% auto;
            padding: 1.5rem;
            width: 90%;
            max-width: 900px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            overflow-x: auto;
        }
        .modal-content h3 {
            color: var(--primary);
            margin-bottom: 1rem;
            font-size: 1.75rem;
        }
        .close {
            float: right;
            font-size: 1.5rem;
            color: var(--secondary);
            cursor: pointer;
            transition: color 0.3s;
        }
        .close:hover {
            color: var(--primary);
        }
        .modal-content table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        .modal-content th, .modal-content td {
            padding: 0.75rem;
            border: 1px solid #dee2e6;
            text-align: left;
            vertical-align: middle;
        }
        .modal-content th {
            background: #f8f9fa;
            color: var(--primary);
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 1;
        }
        .modal-content td {
            color: var(--dark);
            white-space: nowrap;
        }
        /* Ensure existing styles remain compatible */
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .summary-item { padding: 1rem; background: #e9ecef; border-radius: 6px; text-align: center; }
        .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
        .btn { padding: 0.5rem 1rem; border-radius: 4px; text-decoration: none; display: inline-flex; align-items: center; gap: 0.5rem; cursor: pointer; }
        .btn.primary { background: var(--primary); color: white; }
        .btn.primary:hover { background: #0056b3; }
        .notification-feed, .activity-feed { max-height: 300px; overflow-y: auto; }
        .notification-item, .activity-item { padding: 0.75rem; background: #f1f3f5; border-radius: 6px; margin-bottom: 0.5rem; }
    </style>
    <script src="scripts.js" defer></script>
</head>
<body data-alerts="<?php echo htmlspecialchars(json_encode($sessionAlerts), ENT_QUOTES, 'UTF-8'); ?>">
    <div id="page-loader" style="display: none;">
        <div class="loader"></div>
    </div>

    <div class="dashboard">
        <nav class="navbar">
            <div class="navbar-container">
                <?php
                $logoPath = 'images/softnet_logo.png';
                echo file_exists($logoPath)
                    ? '<img src="' . htmlspecialchars($logoPath) . '" alt="Logo" class="header-logo">'
                    : '<span class="header-logo-placeholder"><i class="fas fa-image"></i></span>';
                ?>
                <h2><i class="fas fa-boxes"></i> Inventory Management</h2>
                <a href="process.php?logout=true&_token=<?php echo urlencode($_SESSION['csrf_token']); ?>" class="btn primary" style="background: var(--secondary);" onclick="setLoading(true);">
                    <i class="fas fa-sign-out-alt"></i> Logout
                </a>
            </div>
            <ul class="nav-list">
                <li><a href="#inventory-summary" data-section="inventory-summary">Inventory Summary</a></li>
                <li><a href="#notifications" data-section="notifications">Notifications</a></li>
                <li><a href="#inventory-items" data-section="inventory-items">Inventory</a></li>
                <li><a href="#add-edit-form" data-section="add-edit-form">Add/Edit Item</a></li>
                <li><a href="#csv-import" data-section="csv-import">CSV Import</a></li>
                <li><a href="#batch-update" data-section="batch-update">Batch Update</a></li>
                <li><a href="#activity-log" data-section="activity-log">Activity Log</a></li>
            </ul>
        </nav>

        <div class="container">
            <div class="card" id="inventory-summary">
                <h2><i class="fas fa-chart-bar"></i> Inventory Summary</h2>
                <div id="alert-inventory-summary"></div>
                <?php echo displayAlerts('summary'); ?>
                <div class="summary-grid">
                    <div class="summary-item"><strong>Total Items:</strong> <span id="total-items"><?php echo $summary['total']; ?></span></div>
                    <div class="summary-item"><strong>Low Stock:</strong> <span id="low-stock-items"><?php echo $summary['low_stock']; ?></span></div>
                    <div class="summary-item"><strong>Reorder Needed:</strong> <span id="reorder-needed"><?php echo $summary['reorder_needed']; ?></span></div>
                    <div class="summary-item"><strong>Total Value:</strong> ₱<span id="total-value"><?php echo number_format($summary['total_value'], 2); ?></span></div>
                </div>
            </div>

            <div class="card" id="notifications">
                <h2><i class="fas fa-bell"></i> Notifications</h2>
                <div id="alert-notifications"></div>
                <?php echo displayAlerts('notifications'); ?>
                <div class="notification-header">
                    <form method="post" action="process.php" id="clearNotificationsForm">
                        <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <button type="submit" name="clear_notifications" class="btn primary" style="background: var(--danger);">
                            <i class="fas fa-trash"></i> Clear All
                        </button>
                    </form>
                </div>
                <div class="notification-feed">
                    <?php if ($notifications): ?>
                        <?php foreach ($notifications as $notification): ?>
                            <div class="notification-item" data-id="<?php echo $notification['id']; ?>">
                                <span><?php echo htmlspecialchars($notification['message']); ?></span>
                                <span class="text-muted"><?php echo date('M d, Y h:i A', strtotime($notification['created_at'])); ?></span>
                                <form method="post" action="process.php" class="deleteNotificationForm" style="display: inline;">
                                    <input type="hidden" name="notification_id" value="<?php echo $notification['id']; ?>">
                                    <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <button type="submit" name="delete_notification" class="btn icon delete">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </form>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="notification-item">No notifications available</div>
                    <?php endif; ?>
                </div>
            </div>

            <div class="card" id="inventory-items">
                <h2><i class="fas fa-list"></i> Inventory</h2>
                <div id="alert-inventory-items"></div>
                <?php echo displayAlerts('items'); ?>
                <form method="get" action="javascript:void(0)" class="search-box">
                    <input type="text" id="searchInput" name="search" placeholder="Search items..." value="<?php echo htmlspecialchars($search); ?>" autocomplete="off">
                </form>
                <form method="post" action="process.php" id="bulk-delete-form">
                    <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <div class="bulk-actions">
                        <?php if ($_SESSION['role'] === 'admin'): ?>
                            <button type="submit" name="bulk_delete" class="btn primary" style="background: var(--danger);"><i class="fas fa-trash"></i> Delete Selected</button>
                        <?php endif; ?>
                        <a href="process.php?export_csv=true&_token=<?php echo urlencode($_SESSION['csrf_token']); ?>" class="btn primary export-link" style="background: var(--success);" data-action="export_csv"><i class="fas fa-file-export"></i> Export CSV</a>
                        <a href="javascript:void(0)" class="btn primary" id="viewAllHistoryBtn" style="background: #17a2b8;"><i class="fas fa-history"></i> View History</a>
                    </div>
                    <div class="table-container" id="inventory-table-container">
                        <table class="inventory-table">
                        <thead>
                            <tr>
                                <th><input type="checkbox" id="select-all" class="item-checkbox"></th>
                                <th><a href="javascript:void(0)" data-sort="name">Item Name</a></th>
                                <th><a href="javascript:void(0)" data-sort="quantity">Quantity</a></th>
                                <th><a href="javascript:void(0)" data-sort="price">Price</a></th>
                                <th><a href="javascript:void(0)" data-sort="updated_at">Last Updated</a></th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="inventoryBody">
                                <?php if ($items): ?>
                                    <?php foreach ($items as $item): ?>
                                        <tr>
                                            <td><input type="checkbox" name="item_ids[]" value="<?php echo $item['id']; ?>" class="item-checkbox"></td>
                                            <td class="item-name-column"><?php echo htmlspecialchars($item['name']); ?></td>
                                            <td><?php echo $item['quantity']; ?></td>
                                            <td>₱<?php echo number_format($item['price'], 2); ?></td>
                                            <td class="date-column"><?php echo date('M d, Y h:i A', strtotime($item['updated_at'])); ?></td>
                                            <td class="actions-column">
                                                <div class="action-buttons">
                                                    <a href="javascript:void(0)" class="btn icon edit" data-id="<?php echo $item['id']; ?>"><i class="fas fa-edit"></i></a>
                                                    <?php if ($_SESSION['role'] === 'admin'): ?>
                                                        <a href="javascript:void(0)" class="btn icon delete single-delete" data-id="<?php echo $item['id']; ?>"><i class="fas fa-trash"></i></a>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    <tr class="text-center"><td colspan="6">No items found</td></tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <div class="pagination">
                        <a href="javascript:void(0)" data-page="<?php echo $page - 1; ?>" class="btn pagination-link <?php echo $page <= 1 ? 'disabled' : ''; ?>">Previous</a>
                        <span>Page <?php echo $page; ?> of <?php echo $total_pages; ?></span>
                        <a href="javascript:void(0)" data-page="<?php echo $page + 1; ?>" class="btn pagination-link <?php echo $page >= $total_pages ? 'disabled' : ''; ?>">Next</a>
                    </div>
                </form>
            </div>

            <div class="card" id="add-edit-form">
                <h2><i class="fas fa-plus"></i> Add Item</h2>
                <div id="alert-add-edit-form"></div>
                <?php echo displayAlerts('item'); ?>
                <form method="post" action="process.php" id="item-form" novalidate>
                    <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="name">Item Name</label>
                            <input type="text" id="name" name="name" required>
                        </div>
                        <div class="form-group">
                            <label for="quantity">Quantity</label>
                            <input type="number" id="quantity" name="quantity" min="0" required>
                        </div>
                        <div class="form-group">
                            <label for="price">Price</label>
                            <input type="number" id="price" name="price" step="0.01" min="0" required>
                        </div>
                        <div class="form-group">
                            <label for="low_stock_threshold">Low Stock Threshold</label>
                            <input type="number" id="low_stock_threshold" name="low_stock_threshold" value="5" min="1" required>
                        </div>
                        <div class="form-group">
                            <label for="reorder_threshold">Reorder Threshold</label>
                            <input type="number" id="reorder_threshold" name="reorder_threshold" value="10" min="1" required>
                        </div>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="add_item" class="btn primary"><i class="fas fa-plus"></i> Add Item</button>
                    </div>
                </form>
            </div>

            <div class="card" id="csv-import">
                <h2><i class="fas fa-file-csv"></i> Bulk Add via CSV</h2>
                <div id="alert-csv-import"></div>
                <?php echo displayAlerts('csv_import'); ?>
                <form method="post" action="process.php" enctype="multipart/form-data" id="csvImportForm" novalidate>
                    <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <div class="form-group">
                        <label for="csv_file">Upload CSV File</label>
                        <input type="file" id="csv_file" name="csv_file" accept=".csv" required>
                        <small>Format: name,quantity,price,category,low_stock_threshold,reorder_threshold</small>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="import_csv" class="btn primary"><i class="fas fa-upload"></i> Import</button>
                        <a href="process.php?download_csv=true&_token=<?php echo urlencode($_SESSION['csrf_token']); ?>" class="btn primary export-link" style="background: #17a2b8;" data-action="download_csv"><i class="fas fa-file-csv"></i> Download Template</a>
                    </div>
                </form>
            </div>

            <div class="card" id="batch-update">
                <h2><i class="fas fa-edit"></i> Batch Update</h2>
                <div id="alert-batch-update"></div>
                <?php echo displayAlerts('batch'); ?>
                <form method="post" action="process.php" enctype="multipart/form-data" novalidate>
                    <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <div class="form-group">
                        <label for="batch_csv">Upload CSV File</label>
                        <input type="file" id="batch_csv" name="batch_csv" accept=".csv" required>
                        <small>Format: id,quantity,price,category,low_stock_threshold,reorder_threshold</small>
                    </div>
                    <div class="form-actions">
                        <button type="submit" name="batch_update" class="btn primary"><i class="fas fa-upload"></i> Update</button>
                        <a href="process.php?download_batch_template=true&_token=<?php echo urlencode($_SESSION['csrf_token']); ?>" class="btn primary export-link" style="background: #17a2b8;" data-action="download_batch_template"><i class="fas fa-file-csv"></i> Download Template</a>
                    </div>
                </form>
            </div>

            <div class="card" id="activity-log">
                <h2><i class="fas fa-history"></i> Recent Activity</h2>
                <div id="alert-activity-log"></div>
                <?php echo displayAlerts('activity'); ?>
                <div class="activity-header">
                    <?php if ($_SESSION['role'] === 'admin'): ?>
                        <form method="post" action="process.php" id="clearAllAuditLogsForm" style="display: inline;">
                            <input type="hidden" name="_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <button type="submit" name="clear_all_audit_logs" class="btn primary" style="background: var(--danger);">
                                <i class="fas fa-trash"></i> Clear Logs
                            </button>
                        </form>
                        <a href="process.php?export_logs=true&_token=<?php echo urlencode($_SESSION['csrf_token']); ?>" class="btn primary export-link" style="background: var(--success);" data-action="export_logs">
                            <i class="fas fa-file-export"></i> Export Logs
                        </a>
                    <?php endif; ?>
                </div>
                <form method="get" action="javascript:void(0)" class="filter-box" id="activityFilterForm">
                    <select name="action_filter" id="actionFilter">
                        <option value="">All Actions</option>
                        <option value="CREATE">Create</option>
                        <option value="UPDATE">Update</option>
                        <option value="DELETE">Delete</option>
                    </select>
                </form>
                <div class="activity-feed" id="activityFeed">
                    <?php if ($logs): ?>
                        <?php foreach ($logs as $log): ?>
                            <div class="activity-item" data-id="<?php echo $log['id']; ?>">
                                <div class="activity-icon">
                                    <?php 
                                    $icon = match ($log['action_type']) {
                                        'CREATE' => '<i class="fas fa-plus-circle success"></i>',
                                        'UPDATE' => '<i class="fas fa-pencil-alt warning"></i>',
                                        'DELETE' => '<i class="fas fa-trash-alt danger"></i>',
                                        default => '<i class="fas fa-info-circle"></i>'
                                    };
                                    echo $icon;
                                    ?>
                                </div>
                                <div class="activity-details">
                                    <span class="text-muted"><?php echo date('M d, Y h:i A', strtotime($log['created_at'])); ?></span>
                                    <strong><?php echo htmlspecialchars($log['user']); ?></strong> 
                                    <span class="badge"><?php echo htmlspecialchars($log['action_type']); ?></span> 
                                    <?php echo htmlspecialchars($log['details']); ?>
                                    <?php if ($log['item_id']): ?>
                                        (Item ID: <?php echo htmlspecialchars($log['item_id']); ?>)
                                    <?php endif; ?>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="activity-item"><div class="activity-details">No recent activity</div></div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal for All Item History -->
    <div id="itemHistoryModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">×</span>
            <h3>All Item History</h3>
            <div id="itemHistoryContent">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 8%;">Item ID</th>
                            <th style="width: 20%;">Item Name</th>
                            <th style="width: 12%;">Old Quantity</th>
                            <th style="width: 12%;">New Quantity</th>
                            <th style="width: 12%;">Old Price</th>
                            <th style="width: 12%;">New Price</th>
                            <th style="width: 12%;">User</th>
                            <th style="width: 22%;">Date</th>
                        </tr>
                    </thead>
                    <tbody id="itemHistoryBody"></tbody>
                </table>
            </div>
        </div>
    </div>
</body>
</html>