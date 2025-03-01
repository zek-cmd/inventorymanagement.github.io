<?php
session_start();

if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header("HTTP/1.1 403 Forbidden");
    exit("Not authenticated");
}

$token = htmlspecialchars(strip_tags(filter_input(INPUT_GET, '_token', FILTER_DEFAULT) ?? '')) ?: '';
if (!isset($_SESSION['csrf_token']) || $token !== $_SESSION['csrf_token']) {
    header("HTTP/1.1 403 Forbidden");
    exit("Invalid CSRF token");
}

include 'config/Database.php';

$page = max(1, (int)filter_input(INPUT_GET, 'page', FILTER_SANITIZE_NUMBER_INT) ?? 1);
$items_per_page = 10;
$offset = ($page - 1) * $items_per_page;
$search = filter_input(INPUT_GET, 'search', FILTER_SANITIZE_SPECIAL_CHARS) ?? '';
$sort = filter_input(INPUT_GET, 'sort', FILTER_SANITIZE_SPECIAL_CHARS) ?? 'updated_at';
$sort = in_array($sort, ['name', 'quantity', 'price', 'category', 'updated_at']) ? $sort : 'updated_at';
$order = strtoupper(filter_input(INPUT_GET, 'order', FILTER_SANITIZE_SPECIAL_CHARS) ?? 'DESC');
$order = in_array($order, ['ASC', 'DESC']) ? $order : 'DESC';

try {
    $database = new Database();
    $db = $database->getConnection();

    $stmt = $db->prepare("SELECT DISTINCT i.id, i.name, i.quantity, i.price, i.low_stock_threshold, i.reorder_threshold, i.updated_at FROM items i WHERE LOWER(name) LIKE ? ORDER BY i.$sort $order LIMIT ? OFFSET ?");
    $stmt->execute([strtolower("%$search%"), $items_per_page, $offset]);
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $countStmt = $db->prepare("SELECT COUNT(DISTINCT id) AS total FROM items WHERE name LIKE ?");
    $countStmt->execute(["%$search%"]);
    $total = $countStmt->fetchColumn();
    $total_pages = ceil($total / $items_per_page);

    $summaryStmt = $db->prepare("SELECT 
        COUNT(*) AS total, 
        SUM(CASE WHEN quantity <= low_stock_threshold THEN 1 ELSE 0 END) AS low_stock, 
        SUM(CASE WHEN quantity <= reorder_threshold THEN 1 ELSE 0 END) AS reorder_needed, 
        SUM(quantity * price) AS total_value 
        FROM items");
    $summaryStmt->execute();
    $summaryData = $summaryStmt->fetch(PDO::FETCH_ASSOC);
    $summary = [
        'total' => (int)($summaryData['total'] ?? 0),
        'low_stock' => (int)($summaryData['low_stock'] ?? 0),
        'reorder_needed' => (int)($summaryData['reorder_needed'] ?? 0),
        'total_value' => (float)($summaryData['total_value'] ?? 0.00)
    ];

    ob_start();
    ?>
    <tbody id="inventoryBody">
    <?php
    if ($items) {
        $seenIds = [];
        foreach ($items as $item) {
            if (!in_array($item['id'], $seenIds)) {
                $seenIds[] = $item['id'];
                $low_stock = $item['quantity'] <= $item['low_stock_threshold'] ? 'low-stock' : '';
                $reorder = $item['quantity'] <= $item['reorder_threshold'] ? 'reorder-alert' : '';
                $classes = trim("$low_stock $reorder");
                ?>
              <tr class="<?php echo $classes; ?>">
                <td style="width: 5%;"><input type="checkbox" name="item_ids[]" value="<?php echo $item['id']; ?>" class="item-checkbox"></td>
                <td style="width: 25%;" class="item-name-column"><?php echo htmlspecialchars($item['name']); ?></td>
                <td style="width: 15%;"><?php echo $item['quantity']; ?></td>
                <td style="width: 15%;">₱<?php echo number_format($item['price'], 2); ?></td>
                <td class="date-column" style="width: 30%;"><?php echo date('M d, Y h:i A', strtotime($item['updated_at'])); ?></td>
                <td class="actions-column">
                    <div class="action-buttons">
                        <a href="javascript:void(0)" class="btn icon edit" data-id="<?php echo $item['id']; ?>"><i class="fas fa-edit"></i></a>
                        <?php if ($_SESSION['role'] === 'admin'): ?>
                            <a href="javascript:void(0);" class="btn icon delete single-delete" data-id="<?php echo $item['id']; ?>"><i class="fas fa-trash"></i></a>
                        <?php endif; ?>
                    </div>
                </td>
            </tr>
                            <?php
            }
        }
    } else {
        ?>
        <tr class="text-center"><td colspan="7">No items found</td></tr>
        <?php
    }
    ?>
</tbody>
    <?php
    $tableHtml = ob_get_clean();

    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'success' => true,
        'html' => $tableHtml,
        'summary' => $summary,
        'total' => $total,
        'page' => $page,
        'total_pages' => $total_pages,
        'tab' => 'add-edit-form'
    ], JSON_THROW_ON_ERROR);

} catch (PDOException $e) {
    error_log("Fetch items error: " . $e->getMessage());
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'success' => false,
        'error' => 'Error loading items',
        'html' => '<tbody id="inventoryBody"><tr class="text-center"><td colspan="7">Error loading items</td></tr></tbody>',
        'summary' => ['total' => 0, 'low_stock' => 0, 'reorder_needed' => 0, 'total_value' => 0.00],
        'total' => 0,
        'page' => 1,
        'total_pages' => 1
    ], JSON_THROW_ON_ERROR);
}
?>