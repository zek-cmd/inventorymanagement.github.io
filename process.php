<?php
ob_start();
session_start();
ini_set('display_errors', 0);
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

include 'config/Database.php';

// Utility Functions
function sendJsonResponse($success, $message = '', $error = '', $data = []) {
    while (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'error' => $error,
        'data' => $data
    ], JSON_THROW_ON_ERROR);
    exit();
}

function validateCsrfToken($token) {
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        error_log("CSRF token validation failed: Session token or request token missing");
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

function handleTransaction($db, $callback, $action, $item_id, $details, $log_id = null) {
    try {
        $db->beginTransaction();
        $result = $callback();
        auditLog($db, $action, $item_id, $details, $log_id);
        $db->commit();
        return $result;
    } catch (Exception $e) {
        $db->rollBack();
        error_log("Transaction failed: " . $e->getMessage());
        throw $e;
    }
}

function auditLog($db, $action, $item_id, $details, $log_id = null) {
    try {
        $user = $_SESSION['user'] ?? 'Unknown User';
        if (!in_array($action, ['CREATE', 'UPDATE', 'DELETE'])) {
            throw new Exception("Invalid action type: $action");
        }
        if ($log_id) {
            $stmt = $db->prepare("UPDATE audit_log SET action_type = ?, item_id = ?, details = ?, user = ?, created_at = NOW() WHERE id = ?");
            $stmt->execute([$action, $item_id, $details, $user, $log_id]);
            $affected = $stmt->rowCount();
            if ($affected > 0) {
                error_log("Audit log updated: ID=$log_id, action=$action, item_id=" . ($item_id ?? 'N/A'));
            }
            return $affected > 0;
        } else {
            $stmt = $db->prepare("INSERT INTO audit_log (action_type, item_id, details, user, created_at) VALUES (?, ?, ?, ?, NOW())");
            $stmt->execute([$action, $item_id, $details, $user]);
            $newId = $db->lastInsertId();
            error_log("Audit log inserted: ID=$newId, action=$action, item_id=" . ($item_id ?? 'N/A'));
            return $newId;
        }
    } catch (Exception $e) {
        error_log("auditLog Error: " . $e->getMessage());
        return false;
    }
}

function createNotification($db, $user, $message, $item_id = null, $is_active = 1) {
    try {
        $stmt = $db->prepare("INSERT INTO notifications (user, message, item_id, is_active, created_at) VALUES (?, ?, ?, ?, NOW())");
        $stmt->execute([$user, $message, $item_id, $is_active]);
        error_log("Notification created for user '$user' (Item ID: " . ($item_id ?? 'N/A') . ", Active: $is_active): $message");
        return $db->lastInsertId();
    } catch (PDOException $e) {
        error_log("Notification Error: " . $e->getMessage());
        return false;
    }
}

function deactivateNotifications($db, $item_id) {
    try {
        $stmt = $db->prepare("SELECT quantity, reorder_threshold FROM items WHERE id = ?");
        $stmt->execute([$item_id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($item && $item['quantity'] > $item['reorder_threshold']) {
            $updateStmt = $db->prepare("UPDATE notifications SET is_active = 0 WHERE item_id = ? AND is_active = 1");
            $updateStmt->execute([$item_id]);
            $count = $updateStmt->rowCount();
            if ($count > 0) {
                error_log("Deactivated $count notifications for item ID: $item_id");
            } else {
                error_log("No notifications deactivated for item ID: $item_id (already inactive or none found)");
            }
            return $count > 0;
        } else {
            error_log("Item ID: $item_id not eligible for deactivation - quantity {$item['quantity']} <= reorder_threshold {$item['reorder_threshold']}");
        }
        return false;
    } catch (PDOException $e) {
        error_log("Deactivate notifications error for item ID $item_id: " . $e->getMessage());
        return false;
    }
}

function getInventorySummary($db) {
    try {
        $stmt = $db->prepare("SELECT 
            COUNT(*) AS total, 
            SUM(CASE WHEN quantity <= low_stock_threshold THEN 1 ELSE 0 END) AS low_stock, 
            SUM(CASE WHEN quantity <= reorder_threshold THEN 1 ELSE 0 END) AS reorder_needed, 
            SUM(COALESCE(quantity, 0) * COALESCE(price, 0)) AS total_value 
            FROM items");
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['total' => 0, 'low_stock' => 0, 'reorder_needed' => 0, 'total_value' => 0.00];
        return [
            'total' => (int)$result['total'],
            'low_stock' => (int)$result['low_stock'],
            'reorder_needed' => (int)$result['reorder_needed'],
            'total_value' => (float)$result['total_value']
        ];
    } catch (PDOException $e) {
        error_log("getInventorySummary Error: " . $e->getMessage());
        return ['total' => 0, 'low_stock' => 0, 'reorder_needed' => 0, 'total_value' => 0.00];
    }
}

function getItemById($db, $item_id) {
    try {
        $stmt = $db->prepare("SELECT id, name, quantity, price, low_stock_threshold, reorder_threshold, updated_at FROM items WHERE id = ?");
        $stmt->execute([$item_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    } catch (PDOException $e) {
        error_log("getItemById Error: " . $e->getMessage());
        throw $e;
    }
}

function sanitizeAndValidateItemData($data) {
    $name = htmlspecialchars(strip_tags(trim($data['name'] ?? '')));
    $quantity = (int)($data['quantity'] ?? 0);
    $price = (float)($data['price'] ?? 0.0);
    $low_stock_threshold = (int)($data['low_stock_threshold'] ?? 5);
    $reorder_threshold = (int)($data['reorder_threshold'] ?? 10);

    if (empty($name)) throw new Exception('Item name cannot be empty');
    if ($quantity < 0 || $price < 0 || $low_stock_threshold < 1 || $reorder_threshold < 1) throw new Exception('Invalid values');

    return [
        'name' => $name,
        'quantity' => $quantity,
        'price' => $price,
        'low_stock_threshold' => $low_stock_threshold,
        'reorder_threshold' => $reorder_threshold
    ];
}

function logItemHistory($db, $item_id, $old_quantity, $new_quantity, $old_price, $new_price, $user = null) {
    try {
        $user = $user ?? ($_SESSION['user'] ?? 'Unknown User');
        $stmt = $db->prepare("INSERT INTO item_history (item_id, old_quantity, new_quantity, user, created_at, old_price, new_price) VALUES (?, ?, ?, ?, NOW(), ?, ?)");
        $stmt->execute([$item_id, $old_quantity, $new_quantity, $user, $old_price, $new_price]);
        error_log("Item history logged: item_id=$item_id, old_quantity=$old_quantity, new_quantity=$new_quantity, old_price=$old_price, new_price=$new_price");
    } catch (Exception $e) {
        error_log("logItemHistory Error: " . $e->getMessage());
    }
}

// Main Logic
try {
    $database = new Database();
    $db = $database->getConnection();
    $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';

    if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
        if ($isAjax) sendJsonResponse(false, '', 'Not authenticated');
        else header("Location: login.php");
        exit();
    }

    if (isset($_GET['get_all_item_history'])) {
        while (ob_get_level() > 0) ob_end_clean();
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            error_log("CSRF token validation failed for get_all_item_history");
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        
        try {
            $stmt = $db->prepare("SELECT ih.item_id, i.name AS item_name, ih.old_quantity, ih.new_quantity, ih.old_price, ih.new_price, ih.user, ih.created_at 
                                 FROM item_history ih 
                                 LEFT JOIN items i ON ih.item_id = i.id 
                                 ORDER BY ih.created_at DESC");
            $stmt->execute();
            $history = $stmt->fetchAll(PDO::FETCH_ASSOC);
            sendJsonResponse(true, 'All item history fetched successfully', '', ['history' => $history]);
        } catch (PDOException $e) {
            error_log("Get all item history error: " . $e->getMessage());
            sendJsonResponse(false, '', 'Failed to fetch all item history: Database error');
        }
    }

    if (isset($_GET['logout']) && $_GET['logout'] === 'true') {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        session_destroy();
        sendJsonResponse(true, 'Logged out successfully!');
    }

    if (isset($_GET['get_item'])) {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $item_id = (int)filter_input(INPUT_GET, 'get_item', FILTER_SANITIZE_NUMBER_INT);
        if ($item_id <= 0) {
            sendJsonResponse(false, '', 'Invalid item ID');
        }
        $item = getItemById($db, $item_id);
        if ($item) {
            sendJsonResponse(true, 'Item fetched successfully', '', ['item' => $item]);
        } else {
            sendJsonResponse(false, 'Item not found');
        }
    }

    if (isset($_POST['add_item'])) {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $sanitizedData = sanitizeAndValidateItemData($_POST);
        $item_id = handleTransaction($db, function() use ($db, $sanitizedData) {
            $stmt = $db->prepare("INSERT INTO items (name, quantity, price, low_stock_threshold, reorder_threshold, updated_at) VALUES (?, ?, ?, ?, ?, NOW())");
            $stmt->execute([
                $sanitizedData['name'],
                $sanitizedData['quantity'],
                $sanitizedData['price'],
                $sanitizedData['low_stock_threshold'],
                $sanitizedData['reorder_threshold']
            ]);
            return $db->lastInsertId();
        }, 'CREATE', null, "Added item: {$sanitizedData['name']} (Quantity: {$sanitizedData['quantity']}, Price: {$sanitizedData['price']})");
        
        if ($sanitizedData['quantity'] <= $sanitizedData['low_stock_threshold']) {
            createNotification($db, $_SESSION['user'], "Low stock alert: {$sanitizedData['name']} has {$sanitizedData['quantity']} units remaining.", $item_id);
        } elseif ($sanitizedData['quantity'] <= $sanitizedData['reorder_threshold']) {
            createNotification($db, $_SESSION['user'], "Reorder needed: {$sanitizedData['name']} has {$sanitizedData['quantity']} units remaining.", $item_id);
        }
        
        $summary = getInventorySummary($db);
        sendJsonResponse(true, "Item '{$sanitizedData['name']}' added successfully!", '', ['summary' => $summary]);
    }

    if (isset($_POST['update_item']) && isset($_POST['id'])) {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $id = (int)$_POST['id'];
        $sanitizedData = sanitizeAndValidateItemData($_POST);
        
        $prevItem = getItemById($db, $id);
        handleTransaction($db, function() use ($db, $id, $sanitizedData, $prevItem) {
            $stmt = $db->prepare("UPDATE items SET name = ?, quantity = ?, price = ?, low_stock_threshold = ?, reorder_threshold = ?, updated_at = NOW() WHERE id = ?");
            $stmt->execute([
                $sanitizedData['name'],
                $sanitizedData['quantity'],
                $sanitizedData['price'],
                $sanitizedData['low_stock_threshold'],
                $sanitizedData['reorder_threshold'],
                $id
            ]);

            if ($prevItem['quantity'] != $sanitizedData['quantity'] || $prevItem['price'] != $sanitizedData['price']) {
                logItemHistory($db, $id, $prevItem['quantity'], $sanitizedData['quantity'], $prevItem['price'], $sanitizedData['price']);
            }
        }, 'UPDATE', $id, "Updated item: {$sanitizedData['name']} (ID: $id, Quantity: {$sanitizedData['quantity']}, Price: {$sanitizedData['price']})");
        
        if ($sanitizedData['quantity'] <= $sanitizedData['low_stock_threshold'] && (!isset($prevItem['quantity']) || $prevItem['quantity'] > $sanitizedData['low_stock_threshold'])) {
            createNotification($db, $_SESSION['user'], "Low stock alert: {$sanitizedData['name']} has dropped to {$sanitizedData['quantity']} units.", $id);
        } elseif ($sanitizedData['quantity'] <= $sanitizedData['reorder_threshold'] && (!isset($prevItem['quantity']) || $prevItem['quantity'] > $sanitizedData['reorder_threshold'])) {
            createNotification($db, $_SESSION['user'], "Reorder needed: {$sanitizedData['name']} has {$sanitizedData['quantity']} units remaining.", $id);
        } elseif ($sanitizedData['quantity'] > $sanitizedData['reorder_threshold'] && $prevItem && $prevItem['quantity'] <= $prevItem['reorder_threshold']) {
            $deactivated = deactivateNotifications($db, $id);
            if ($deactivated) {
                createNotification($db, $_SESSION['user'], "Restock completed: {$sanitizedData['name']} now has {$sanitizedData['quantity']} units.", $id, 0);
            }
        }
        
        $summary = getInventorySummary($db);
        sendJsonResponse(true, "Item '{$sanitizedData['name']}' updated successfully!", '', ['summary' => $summary]);
    }

    if (isset($_GET['delete']) && $_SESSION['role'] === 'admin') {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $item_id = (int)filter_input(INPUT_GET, 'delete', FILTER_SANITIZE_NUMBER_INT);
        $result = handleTransaction($db, function() use ($db, $item_id) {
            $stmt = $db->prepare("SELECT id, name FROM items WHERE id = ?");
            $stmt->execute([$item_id]);
            $item = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($item) {
                $db->prepare("DELETE FROM notifications WHERE item_id = ?")->execute([$item_id]);
                $db->prepare("DELETE FROM item_history WHERE item_id = ?")->execute([$item_id]);
                $db->prepare("DELETE FROM items WHERE id = ?")->execute([$item_id]);
                return $item;
            }
            return null;
        }, 'DELETE', $item_id, "Deleted item: " . ($result['name'] ?? 'Unknown') . " (ID: $item_id)");
        $summary = getInventorySummary($db);
        if ($result) {
            sendJsonResponse(true, "Item '{$result['name']}' deleted successfully!", '', ['summary' => $summary]);
        } else {
            sendJsonResponse(false, 'Item not found');
        }
    }

    if (isset($_POST['bulk_delete']) && $_SESSION['role'] === 'admin') {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $item_ids = array_map('intval', $_POST['item_ids'] ?? []);
        if (empty($item_ids)) {
            sendJsonResponse(false, '', 'No items selected');
        }
        $deleted_items = handleTransaction($db, function() use ($db, $item_ids) {
            $placeholders = implode(',', array_fill(0, count($item_ids), '?'));
            $stmt = $db->prepare("SELECT id, name FROM items WHERE id IN ($placeholders)");
            $stmt->execute($item_ids);
            $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
            if ($items) {
                $db->prepare("DELETE FROM notifications WHERE item_id IN ($placeholders)")->execute($item_ids);
                $db->prepare("DELETE FROM item_history WHERE item_id IN ($placeholders)")->execute($item_ids);
                $db->prepare("DELETE FROM items WHERE id IN ($placeholders)")->execute($item_ids);
                foreach ($items as $item) {
                    auditLog($db, 'DELETE', $item['id'], "Bulk deleted item: {$item['name']} (ID: {$item['id']})");
                }
            }
            return $items;
        }, 'DELETE', null, "Bulk deleted " . count($item_ids) . " items");
        $summary = getInventorySummary($db);
        sendJsonResponse(true, "Deleted " . count($deleted_items) . " items successfully!", '', ['summary' => $summary]);
    }

    if (isset($_POST['import_csv']) && isset($_FILES['csv_file'])) {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $file = $_FILES['csv_file'];
        if ($file['error'] === UPLOAD_ERR_OK && in_array($file['type'], ['text/csv', 'application/vnd.ms-excel'])) {
            $csv = fopen($file['tmp_name'], 'r');
            if ($csv === false) {
                sendJsonResponse(false, '', 'Failed to open CSV file');
            }
            fgetcsv($csv); // Skip header
            $imported = 0;
            while (($row = fgetcsv($csv)) !== false) {
                if (count($row) >= 5) {
                    $data = [
                        'name' => $row[0],
                        'quantity' => $row[1],
                        'price' => $row[2],
                        'low_stock_threshold' => $row[3],
                        'reorder_threshold' => $row[4]
                    ];
                    try {
                        $sanitizedData = sanitizeAndValidateItemData($data);
                        $item_id = handleTransaction($db, function() use ($db, $sanitizedData) {
                            $stmt = $db->prepare("INSERT INTO items (name, quantity, price, low_stock_threshold, reorder_threshold, updated_at) VALUES (?, ?, ?, ?, ?, NOW())");
                            $stmt->execute([
                                $sanitizedData['name'],
                                $sanitizedData['quantity'],
                                $sanitizedData['price'],
                                $sanitizedData['low_stock_threshold'],
                                $sanitizedData['reorder_threshold']
                            ]);
                            return $db->lastInsertId();
                        }, 'CREATE', null, "Imported: {$sanitizedData['name']} (Quantity: {$sanitizedData['quantity']}, Price: {$sanitizedData['price']})");
                        $imported++;
                        
                        if ($sanitizedData['quantity'] <= $sanitizedData['low_stock_threshold']) {
                            createNotification($db, $_SESSION['user'], "Low stock alert: {$sanitizedData['name']} has {$sanitizedData['quantity']} units remaining.", $item_id);
                        } elseif ($sanitizedData['quantity'] <= $sanitizedData['reorder_threshold']) {
                            createNotification($db, $_SESSION['user'], "Reorder needed: {$sanitizedData['name']} has {$sanitizedData['quantity']} units remaining.", $item_id);
                        }
                    } catch (Exception $e) {
                        error_log("CSV import error for row: " . implode(',', $row) . " - " . $e->getMessage());
                    }
                }
            }
            fclose($csv);
            $summary = getInventorySummary($db);
            sendJsonResponse(true, "Imported $imported items successfully!", '', ['summary' => $summary]);
        } else {
            sendJsonResponse(false, '', 'Invalid CSV file or upload error');
        }
    }

    if (isset($_POST['batch_update']) && isset($_FILES['batch_csv'])) {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $file = $_FILES['batch_csv'];
        if ($file['error'] === UPLOAD_ERR_OK && in_array($file['type'], ['text/csv', 'application/vnd.ms-excel'])) {
            $csv = fopen($file['tmp_name'], 'r');
            if ($csv === false) {
                sendJsonResponse(false, '', 'Failed to open CSV file');
            }
            fgetcsv($csv); // Skip header
            $updated = 0;
            while (($row = fgetcsv($csv)) !== false) {
                if (count($row) >= 5) {
                    $id = (int)($row[0] ?? 0);
                    $data = [
                        'name' => '',
                        'quantity' => $row[1],
                        'price' => $row[2],
                        'low_stock_threshold' => $row[3],
                        'reorder_threshold' => $row[4]
                    ];
                    try {
                        $sanitizedData = sanitizeAndValidateItemData($data);
                        $prevItem = getItemById($db, $id);
                        handleTransaction($db, function() use ($db, $id, $sanitizedData) {
                            $stmt = $db->prepare("UPDATE items SET quantity = ?, price = ?, low_stock_threshold = ?, reorder_threshold = ?, updated_at = NOW() WHERE id = ?");
                            $stmt->execute([
                                $sanitizedData['quantity'],
                                $sanitizedData['price'],
                                $sanitizedData['low_stock_threshold'],
                                $sanitizedData['reorder_threshold'],
                                $id
                            ]);
                        }, 'UPDATE', $id, "Batch updated item ID: $id (Quantity: {$sanitizedData['quantity']}, Price: {$sanitizedData['price']})");
                        $updated++;
                        
                        $item = getItemById($db, $id);
                        if ($item) {
                            if ($item['quantity'] <= $item['low_stock_threshold'] && (!isset($prevItem['quantity']) || $prevItem['quantity'] > $item['low_stock_threshold'])) {
                                createNotification($db, $_SESSION['user'], "Low stock alert: {$item['name']} has dropped to {$item['quantity']} units.", $id);
                            } elseif ($item['quantity'] <= $item['reorder_threshold'] && (!isset($prevItem['quantity']) || $prevItem['quantity'] > $item['reorder_threshold'])) {
                                createNotification($db, $_SESSION['user'], "Reorder needed: {$item['name']} has {$item['quantity']} units remaining.", $id);
                            } elseif ($prevItem['quantity'] <= $prevItem['reorder_threshold'] && $item['quantity'] > $item['reorder_threshold']) {
                                deactivateNotifications($db, $id);
                                createNotification($db, $_SESSION['user'], "Restock completed: {$item['name']} now has {$item['quantity']} units.", $id);
                            }
                        }
                    } catch (Exception $e) {
                        error_log("Batch update error for ID $id: " . $e->getMessage());
                    }
                }
            }
            fclose($csv);
            $summary = getInventorySummary($db);
            sendJsonResponse(true, "Updated $updated items successfully!", '', ['summary' => $summary]);
        } else {
            sendJsonResponse(false, '', 'Invalid CSV file or upload error');
        }
    }

    if (isset($_GET['export_csv'])) {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        while (ob_get_level() > 0) ob_end_clean();
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="inventory_export_' . date('Y-m-d_H-i-s') . '.csv"');
        $output = fopen('php://output', 'w');
        if ($output === false) {
            error_log("Failed to open php://output for export_csv");
            sendJsonResponse(false, '', 'Server error during export');
        }
        fputcsv($output, ['name', 'quantity', 'price', 'low_stock_threshold', 'reorder_threshold']);
        $stmt = $db->query("SELECT name, quantity, price, low_stock_threshold, reorder_threshold FROM items ORDER BY updated_at DESC");
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) fputcsv($output, array_values($row));
        fclose($output);
        exit();
    }

    if (isset($_GET['fetch_activity_logs']) && isset($_GET['action_filter'])) {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $action_filter = htmlspecialchars(strip_tags(filter_input(INPUT_GET, 'action_filter', FILTER_DEFAULT) ?? ''));
        $logQuery = "SELECT * FROM audit_log WHERE 1=1";
        $params = [];
        if (!empty($action_filter) && in_array($action_filter, ['CREATE', 'UPDATE', 'DELETE'])) {
            $logQuery .= " AND action_type = ?";
            $params[] = $action_filter;
        }
        $logQuery .= " ORDER BY created_at DESC LIMIT 10";
        try {
            $logStmt = $db->prepare($logQuery);
            $logStmt->execute($params);
            $logs = $logStmt->fetchAll(PDO::FETCH_ASSOC);
            $html = '';
            foreach ($logs as $log) {
                $icon = match ($log['action_type']) {
                    'CREATE' => '<i class="fas fa-plus-circle success"></i>',
                    'UPDATE' => '<i class="fas fa-pencil-alt warning"></i>',
                    'DELETE' => '<i class="fas fa-trash-alt danger"></i>',
                    default => '<i class="fas fa-info-circle"></i>'
                };
                $html .= '<div class="activity-item" data-id="' . $log['id'] . '"><div class="activity-icon">' . $icon . '</div><div class="activity-details">';
                $html .= '<span class="text-muted">' . date('M d, Y h:i A', strtotime($log['created_at'])) . '</span>';
                $html .= '<strong>' . htmlspecialchars($log['user']) . '</strong> ';
                $html .= '<span class="badge">' . htmlspecialchars($log['action_type']) . '</span> ';
                $html .= htmlspecialchars($log['details']);
                if ($log['item_id']) {
                    $html .= ' (Item ID: ' . htmlspecialchars($log['item_id']) . ')';
                }
                $html .= '</div></div>';
            }
            if (empty($logs)) {
                $html = '<div class="activity-item"><div class="activity-details">No recent activity available</div></div>';
            }
            sendJsonResponse(true, 'Activity logs fetched successfully!', '', ['html' => $html]);
        } catch (PDOException $e) {
            error_log("Fetch activity logs error: " . $e->getMessage());
            sendJsonResponse(false, '', 'Failed to fetch activity logs');
        }
    }

    if (isset($_POST['clear_notifications'])) {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        try {
            $stmt = $db->prepare("DELETE FROM notifications WHERE user = ? AND (is_active = 0 OR item_id IS NULL)");
            $stmt->execute([$_SESSION['user']]);
            $count = $stmt->rowCount();
            sendJsonResponse(true, $count > 0 ? "Cleared $count non-persistent notifications successfully!" : 'No non-persistent notifications to clear');
        } catch (PDOException $e) {
            error_log("Clear notifications error: " . $e->getMessage());
            sendJsonResponse(false, '', 'Failed to clear notifications');
        }
    }

    if (isset($_POST['delete_notification']) && isset($_POST['notification_id'])) {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        $notification_id = (int)$_POST['notification_id'];
        try {
            $checkStmt = $db->prepare("SELECT n.is_active, n.item_id, i.quantity, i.reorder_threshold 
                                       FROM notifications n 
                                       LEFT JOIN items i ON n.item_id = i.id 
                                       WHERE n.id = ? AND n.user = ?");
            $checkStmt->execute([$notification_id, $_SESSION['user']]);
            $notification = $checkStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$notification) {
                sendJsonResponse(false, 'Notification not found or not authorized');
            }
            if ($notification['is_active'] == 1 && $notification['item_id'] !== null && 
                $notification['quantity'] <= $notification['reorder_threshold']) {
                sendJsonResponse(false, 'Cannot delete active item-specific notification until restocked');
            }
            
            $stmt = $db->prepare("DELETE FROM notifications WHERE id = ? AND user = ?");
            $stmt->execute([$notification_id, $_SESSION['user']]);
            if ($stmt->rowCount() > 0) {
                sendJsonResponse(true, 'Notification deleted successfully!');
            } else {
                sendJsonResponse(false, 'Notification not found or not authorized');
            }
        } catch (PDOException $e) {
            error_log("Delete notification error: " . $e->getMessage());
            sendJsonResponse(false, '', 'Failed to delete notification');
        }
    }

    if (isset($_POST['clear_all_audit_logs']) && $_SESSION['role'] === 'admin') {
        $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        try {
            $stmt = $db->prepare("DELETE FROM audit_log");
            $stmt->execute();
            $count = $stmt->rowCount();
            error_log("Cleared audit logs: $count rows affected");
            sendJsonResponse(true, "Cleared $count audit logs successfully!");
        } catch (PDOException $e) {
            error_log("Clear audit logs error: " . $e->getMessage());
            sendJsonResponse(false, '', 'Failed to clear audit logs');
        }
    }

    if (isset($_GET['export_logs']) && $_SESSION['role'] === 'admin') {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        while (ob_get_level() > 0) ob_end_clean();
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="audit_logs_' . date('Y-m-d_H-i-s') . '.csv"');
        $output = fopen('php://output', 'w');
        if ($output === false) {
            error_log("Failed to open php://output for export_logs");
            exit();
        }
        fputcsv($output, ['id', 'action_type', 'item_id', 'details', 'user', 'created_at']);
        $stmt = $db->query("SELECT id, action_type, item_id, details, user, created_at FROM audit_log ORDER BY created_at DESC");
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            fputcsv($output, array_values($row));
        }
        fclose($output);
        exit();
    }

    if (isset($_GET['download_csv'])) {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        while (ob_get_level() > 0) ob_end_clean();
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="bulk_add_template.csv"');
        $output = fopen('php://output', 'w');
        if ($output === false) {
            error_log("Failed to open php://output for download_csv");
            exit();
        }
        fputcsv($output, ['name', 'quantity', 'price', 'low_stock_threshold', 'reorder_threshold']);
        fputcsv($output, ['Item Name 1', 10, 19.99, 5, 10]);
        fputcsv($output, ['Item Name 2', 5, 499.95, 5, 10]);
        fclose($output);
        exit();
    }

    if (isset($_GET['download_batch_template'])) {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        while (ob_get_level() > 0) ob_end_clean();
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="batch_update_template.csv"');
        $output = fopen('php://output', 'w');
        if ($output === false) {
            error_log("Failed to open php://output for download_batch_template");
            exit();
        }
        fputcsv($output, ['id', 'quantity', 'price', 'low_stock_threshold', 'reorder_threshold']);
        fputcsv($output, [1, 50, 15.99, 5, 10]);
        fclose($output);
        exit();
    }

    if (isset($_GET['fetch_notifications'])) {
        $token = filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '';
        if (!validateCsrfToken($token)) {
            sendJsonResponse(false, '', 'Invalid CSRF token');
        }
        try {
            $stmt = $db->prepare("SELECT id, message, item_id, created_at FROM notifications WHERE user = ? AND is_active = 1 ORDER BY created_at DESC LIMIT 10");
            $stmt->execute([$_SESSION['user']]);
            $notifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $html = '';
            if ($notifications) {
                foreach ($notifications as $notification) {
                    $html .= '<div class="notification-item" data-id="' . $notification['id'] . '">';
                    $html .= '<span class="text-muted">' . date('M d, Y h:i A', strtotime($notification['created_at'])) . '</span>';
                    $html .= '<p>' . htmlspecialchars($notification['message']) . ' (Item ID: ' . ($notification['item_id'] ?? 'N/A') . ')</p>';
                    $html .= '<form class="deleteNotificationForm" method="post">';
                    $html .= '<input type="hidden" name="_token" value="' . htmlspecialchars($_SESSION['csrf_token']) . '">';
                    $html .= '<input type="hidden" name="notification_id" value="' . $notification['id'] . '">';
                    $html .= '<button type="submit" class="btn icon"><i class="fas fa-trash"></i></button>';
                    $html .= '</form>';
                    $html .= '</div>';
                }
            } else {
                $html = '<div class="notification-item">No active notifications available</div>';
            }
            sendJsonResponse(true, 'Notifications fetched successfully!', '', ['html' => $html]);
        } catch (PDOException $e) {
            error_log("Fetch notifications error: " . $e->getMessage());
            sendJsonResponse(false, '', 'Failed to fetch notifications');
        }
    }

} catch (Exception $e) {
    error_log("Global Exception: " . $e->getMessage());
    if ($isAjax) sendJsonResponse(false, '', 'Unexpected server error: ' . $e->getMessage());
    else {
        $_SESSION['error'] = 'Unexpected server error occurred';
        header("Location: index.php");
    }
}
?>