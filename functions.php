<?php
session_start();

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

function createNotification($db, $user, $message) {
    try {
        $stmt = $db->prepare("INSERT INTO notifications (user, message, created_at) VALUES (?, ?, NOW())");
        $stmt->execute([$user, $message]);
        error_log("Notification created for user '$user': $message");
        return $db->lastInsertId();
    } catch (PDOException $e) {
        error_log("Notification Error: " . $e->getMessage());
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
        $stmt = $db->prepare("SELECT * FROM items WHERE id = ?");
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
    $category = htmlspecialchars(strip_tags(trim($data['category'] ?? '')));
    $low_stock_threshold = (int)($data['low_stock_threshold'] ?? 5);
    $reorder_threshold = (int)($data['reorder_threshold'] ?? 10);

    if (empty($name)) {
        throw new Exception('Item name cannot be empty');
    }
    if ($quantity < 0 || $price < 0 || $low_stock_threshold < 1 || $reorder_threshold < 1) {
        throw new Exception('Invalid values');
    }
    if (!in_array($category, ['Clothing', 'Electronics', 'Books', 'Furniture', 'Other'])) {
        throw new Exception('Invalid category');
    }

    return [
        'name' => $name,
        'quantity' => $quantity,
        'price' => $price,
        'category' => $category,
        'low_stock_threshold' => $low_stock_threshold,
        'reorder_threshold' => $reorder_threshold
    ];
}

if (isset($_POST['add_item'])) {
    $token = filter_input(INPUT_POST, '_token', FILTER_DEFAULT) ?? '';
    if (!validateCsrfToken($token)) {
        sendJsonResponse(false, '', 'Invalid CSRF token');
    }
    $sanitizedData = sanitizeAndValidateItemData($_POST);
    $item_id = handleTransaction($db, function() use ($db, $sanitizedData) {
        $stmt = $db->prepare("INSERT INTO items (name, quantity, price, category, low_stock_threshold, reorder_threshold, updated_at) VALUES (?, ?, ?, ?, ?, ?, NOW())");
        $stmt->execute([
            $sanitizedData['name'],
            $sanitizedData['quantity'],
            $sanitizedData['price'],
            $sanitizedData['category'],
            $sanitizedData['low_stock_threshold'],
            $sanitizedData['reorder_threshold']
        ]);
        $new_id = $db->lastInsertId();
        if ($new_id === null || $new_id <= 0) {
            error_log("Failed to retrieve item_id for new item: {$sanitizedData['name']}");
        }
        return $new_id;
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
    handleTransaction($db, function() use ($db, $id, $sanitizedData) {
        $stmt = $db->prepare("UPDATE items SET name = ?, quantity = ?, price = ?, category = ?, low_stock_threshold = ?, reorder_threshold = ?, updated_at = NOW() WHERE id = ?");
        $stmt->execute([
            $sanitizedData['name'],
            $sanitizedData['quantity'],
            $sanitizedData['price'],
            $sanitizedData['category'],
            $sanitizedData['low_stock_threshold'],
            $sanitizedData['reorder_threshold'],
            $id
        ]);
    }, 'UPDATE', $id, "Updated item: {$sanitizedData['name']} (ID: $id, Quantity: {$sanitizedData['quantity']}, Price: {$sanitizedData['price']})");
    
    // Notification logic
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
            deactivateNotifications($db, $item_id); // Deactivate notifications before deletion
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
?>