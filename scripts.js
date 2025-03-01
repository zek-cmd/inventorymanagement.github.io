// Utility Functions
const setLoading = (loading) => {
    const loader = document.getElementById('page-loader');
    if (loader) {
        loader.style.display = loading ? 'flex' : 'none';
        loader.classList.toggle('visible', loading);
    }
};

const showAlert = (sectionId, message, type, duration = 5000) => {
    const alertContainer = document.getElementById(`alert-${sectionId}`);
    if (!alertContainer) {
        console.warn(`Alert container for section ${sectionId} not found`);
        return;
    }
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert ${type}`;
    alertDiv.innerHTML = `<i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i> ${message}`;
    alertContainer.appendChild(alertDiv);
    setTimeout(() => alertDiv.remove(), duration);
};

const showSessionAlerts = () => {
    const sessionAlerts = JSON.parse(document.body.dataset.alerts || '{}');
    for (const [sectionId, alerts] of Object.entries(sessionAlerts)) {
        if (alerts.message) showAlert(sectionId, alerts.message, 'success');
        if (alerts.error) showAlert(sectionId, alerts.error, 'error');
    }
};

const persistState = () => {
    const state = {
        scrollY: window.scrollY,
        activeSection: document.querySelector('.card:target')?.id || document.activeElement?.closest('.card')?.id || 'inventory-items',
        search: document.getElementById('searchInput')?.value || '',
        page: sessionStorage.getItem('currentPage') || 1,
        sort: sessionStorage.getItem('sort') || 'updated_at',
        order: sessionStorage.getItem('order') || 'DESC',
        // Always set editMode to false and formData to empty on persist
        editMode: false,
        formData: {}
    };
    sessionStorage.setItem('inventoryState', JSON.stringify(state));
};

const restoreState = () => {
    const state = JSON.parse(sessionStorage.getItem('inventoryState') || '{}');
    if (state.scrollY) window.scrollTo(0, state.scrollY);
    if (state.search) document.getElementById('searchInput').value = state.search;
    if (state.activeSection) {
        const section = document.getElementById(state.activeSection);
        if (section) section.scrollIntoView({ behavior: 'smooth' });
    }
    // Always reset the form to "Add Item Individually" on refresh
    cancelEdit();
    sessionStorage.setItem('currentPage', state.page || 1);
    sessionStorage.setItem('sort', state.sort || 'updated_at');
    sessionStorage.setItem('order', state.order || 'DESC');
};
const showAllItemHistory = () => {
    setLoading(true);
    fetch(`process.php?get_all_item_history=true&_token=${encodeURIComponent(document.querySelector('meta[name="csrf-token"]').content)}`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => response.text())
    .then(text => {
        console.log('Raw server response:', text);
        try {
            const data = JSON.parse(text);
            if (!data.success) throw new Error(data.error || 'Failed to fetch history');
            const history = data.data.history;
            const tbody = document.getElementById('itemHistoryBody');
            tbody.innerHTML = '';
            if (history.length > 0) {
                history.forEach(row => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${row.item_id || '-'}</td>
                        <td>${row.item_name || '-'}</td>
                        <td>${row.old_quantity !== null ? row.old_quantity : '-'}</td>
                        <td>${row.new_quantity !== null ? row.new_quantity : '-'}</td>
                        <td>₱${row.old_price !== null ? Number(row.old_price).toFixed(2) : '-'}</td>
                        <td>₱${row.new_price !== null ? Number(row.new_price).toFixed(2) : '-'}</td>
                        <td>${row.user || '-'}</td>
                        <td>${row.created_at ? new Date(row.created_at).toLocaleString() : '-'}</td>
                    `;
                    tbody.appendChild(tr);
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="8">No history available</td></tr>';
            }
            document.getElementById('itemHistoryModal').style.display = 'block';
        } catch (e) {
            console.error('Failed to parse JSON:', e);
            showAlert('inventory-items', 'Invalid JSON response from server: ' + text, 'error');
        }
    })
    .catch(error => {
        console.error('Fetch all item history error:', error);
        showAlert('inventory-items', `Failed to fetch history: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const closeModal = () => {
    document.getElementById('itemHistoryModal').style.display = 'none';
};

// Core Functions
const refreshInventoryTableAndSummary = () => {
    setLoading(true);
    const params = {
        search: document.getElementById('searchInput')?.value || '',
        page: sessionStorage.getItem('currentPage') || 1,
        sort: sessionStorage.getItem('sort') || 'updated_at',
        order: sessionStorage.getItem('order') || 'DESC',
        _token: document.querySelector('meta[name="csrf-token"]')?.content || ''
    };
    fetch(`fetch_items.php?${new URLSearchParams(params).toString()}`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        return response.json();
    })
    .then(data => {
        if (data.success) {
            document.getElementById('inventoryBody').innerHTML = data.html;
            document.getElementById('total-items').textContent = data.summary.total;
            document.getElementById('low-stock-items').textContent = data.summary.low_stock;
            document.getElementById('reorder-needed').textContent = data.summary.reorder_needed;
            document.getElementById('total-value').textContent = Number(data.summary.total_value).toFixed(2);

            // Update pagination controls
            const pagination = document.querySelector('.pagination');
            if (pagination) {
                const prevLink = pagination.querySelector('.pagination-link:first-child');
                const nextLink = pagination.querySelector('.pagination-link:last-child');
                const pageSpan = pagination.querySelector('span');

                prevLink.dataset.page = data.page - 1;
                nextLink.dataset.page = data.page + 1;
                pageSpan.textContent = `Page ${data.page} of ${data.total_pages}`;

                prevLink.classList.toggle('disabled', data.page <= 1);
                nextLink.classList.toggle('disabled', data.page >= data.total_pages);
            }

            updateSelectAllState();
            persistState();
        } else {
            throw new Error(data.error || 'Failed to refresh inventory');
        }
    })
    .catch(error => {
        console.error('Refresh inventory error:', error);
        showAlert('inventory-items', `Failed to refresh: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleItemAddUpdate = (e) => {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    const isEdit = formData.get('id') && !isNaN(parseInt(formData.get('id')));
    formData.append(isEdit ? 'update_item' : 'add_item', '1');

    setLoading(true);
    fetch('process.php', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        return response.json();
    })
    .then(data => {
        const message = data.message || (isEdit ? 'Item updated successfully!' : 'Item added successfully!');
        showAlert('add-edit-form', data.success ? message : (data.error || 'Operation failed'), data.success ? 'success' : 'error');
        if (data.success) {
            refreshInventoryTableAndSummary();
            fetchNotifications(); // Add this to refresh notifications
            if (!isEdit) form.reset();
            else cancelEdit();
            if (data.data?.summary) {
                document.getElementById('total-items').textContent = data.data.summary.total;
                document.getElementById('low-stock-items').textContent = data.data.summary.low_stock;
                document.getElementById('reorder-needed').textContent = data.data.summary.reorder_needed;
                document.getElementById('total-value').textContent = Number(data.data.summary.total_value).toFixed(2);
            }
        }
    })
    .catch(error => {
        console.error('Add/Update item error:', error);
        showAlert('add-edit-form', `Operation failed: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleEditClick = (itemId) => {
    setLoading(true);
    fetch(`process.php?get_item=${encodeURIComponent(itemId)}&_token=${encodeURIComponent(document.querySelector('meta[name="csrf-token"]').content)}`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        return response.json();
    })
    .then(data => {
        if (!data.success) {
            throw new Error(data.error || 'Server returned failure');
        }
        if (!data.data || !data.data.item) {
            throw new Error('Invalid or missing item data');
        }
        const item = data.data.item;
        const card = document.getElementById('add-edit-form');
        const form = document.getElementById('item-form');
        const title = card?.querySelector('h2');
        if (!card || !form || !title) {
            throw new Error('Required DOM elements not found');
        }
        title.innerHTML = '<i class="fas fa-edit"></i> Edit Item';
        form.querySelector('input[name="name"]').value = item.name || '';
        form.querySelector('input[name="quantity"]').value = item.quantity || 0;
        form.querySelector('input[name="price"]').value = item.price || 0;
        form.querySelector('input[name="low_stock_threshold"]').value = item.low_stock_threshold || 5;
        form.querySelector('input[name="reorder_threshold"]').value = item.reorder_threshold || 10;
        let idInput = form.querySelector('input[name="id"]');
        if (!idInput) {
            idInput = document.createElement('input');
            idInput.type = 'hidden';
            idInput.name = 'id';
            form.appendChild(idInput);
        }
        idInput.value = item.id || '';
        form.querySelector('.form-actions').innerHTML = `
            <button type="submit" class="btn primary"><i class="fas fa-save"></i> Update Item</button>
            <button type="button" class="btn primary cancel" onclick="cancelEdit()"><i class="fas fa-times"></i> Cancel</button>
        `;
        card.classList.add('edit-mode');
        card.scrollIntoView({ behavior: 'smooth' });
        
        persistState();
    })
    .catch(error => {
        console.error('Edit item error:', error);
        showAlert('add-edit-form', `Failed to load item: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleDelete = (itemId) => {
    cancelEdit();
    if (!confirm('Are you sure you want to delete this item?')) return;
    setLoading(true);
    fetch(`process.php?delete=${encodeURIComponent(itemId)}&_token=${encodeURIComponent(document.querySelector('meta[name="csrf-token"]').content)}`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        return response.json();
    })
    .then(data => {
        const message = data.message || 'Item deleted successfully!';
        showAlert('inventory-items', data.success ? message : (data.error || 'Delete failed'), data.success ? 'success' : 'error');
        if (data.success) {
            refreshInventoryTableAndSummary();
            fetchNotifications(); // Refresh notifications to remove deleted item alerts
        }
    })
    .catch(error => {
        console.error('Delete item error:', error);
        showAlert('inventory-items', `Delete failed: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleBulkDelete = (form) => {
    cancelEdit();
    if (!confirm('Are you sure you want to delete the selected items?')) return;
    setLoading(true);
    const formData = new FormData(form);
    formData.append('bulk_delete', 'true');
    fetch('process.php', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        return response.json();
    })
    .then(data => {
        const message = data.message || 'Items deleted successfully!';
        showAlert('inventory-items', data.success ? message : (data.error || 'Bulk delete failed'), data.success ? 'success' : 'error');
        if (data.success) {
            refreshInventoryTableAndSummary();
            fetchNotifications(); // Refresh notifications to remove deleted item alerts
        }
    })
    .catch(error => {
        console.error('Bulk delete error:', error);
        showAlert('inventory-items', `Bulk delete failed: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};
const handleCsvImport = (form) => {
    setLoading(true);
    const formData = new FormData(form);
    formData.append('import_csv', '1');
    fetch('process.php', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        return response.json();
    })
    .then(data => {
        const message = data.message || 'CSV import successful!';
        showAlert('csv-import', data.success ? message : (data.error || 'Import failed'), data.success ? 'success' : 'error');
        if (data.success) {
            form.reset();
            refreshInventoryTableAndSummary();
        }
    })
    .catch(error => {
        console.error('CSV import error:', error);
        showAlert('csv-import', `Import failed: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleBatchUpdate = (form) => {
    setLoading(true);
    const formData = new FormData(form);
    formData.append('batch_update', '1');
    fetch('process.php', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        return response.json();
    })
    .then(data => {
        const message = data.message || 'Batch update successful!';
        showAlert('batch-update', data.success ? message : (data.error || 'Batch update failed'), data.success ? 'success' : 'error');
        if (data.success) refreshInventoryTableAndSummary();
    })
    .catch(error => {
        console.error('Batch update error:', error);
        showAlert('batch-update', `Batch update failed: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleExportDownload = (e, action) => {
    e.preventDefault();
    setLoading(true);
    fetch(`process.php?${action}=true&_token=${encodeURIComponent(document.querySelector('meta[name="csrf-token"]').content)}`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
    .then(response => {
        if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
        const filename = response.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1] || `${action}_${Date.now()}.csv`;
        return response.blob().then(blob => ({ blob, filename }));
    })
    .then(({ blob, filename }) => {
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        showAlert('inventory-items', 'Download successful!', 'success');
    })
    .catch(error => {
        console.error('Export download error:', error);
        showAlert('inventory-items', `Download failed: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleClearNotifications = (e) => {
    e.preventDefault();
    setLoading(true);
    const form = document.getElementById('clearNotificationsForm');
    if (!form) {
        console.error('Clear notifications form not found');
        showAlert('notifications', 'Form not found', 'error');
        setLoading(false);
        return;
    }
    const formData = new FormData(form);
    formData.append('clear_notifications', 'true');
    fetch('process.php', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
        return response.json();
    })
    .then(data => {
        showAlert('notifications', data.message || 'Non-persistent notifications cleared', data.success ? 'success' : 'error');
        if (data.success) {
            // Refresh notifications instead of clearing all
            fetchNotifications(); // Add this function to refresh
        }
    })
    .catch(error => {
        console.error('Clear notifications error:', error);
        showAlert('notifications', `Failed to clear notifications: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

// New function to fetch notifications
const fetchNotifications = () => {
    setLoading(true);
    fetch(`process.php?fetch_notifications=true&_token=${encodeURIComponent(document.querySelector('meta[name="csrf-token"]').content)}`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error ${response.status}`);
        return response.json();
    })
    .then(data => {
        if (data.success) {
            document.querySelector('.notification-feed').innerHTML = data.data.html;
        }
    })
    .catch(error => {
        console.error('Fetch notifications error:', error);
        showAlert('notifications', `Failed to fetch notifications: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleDeleteNotification = (form) => {
    if (!form) {
        console.error('Notification form not provided');
        showAlert('notifications', 'Form error', 'error');
        return;
    }
    setLoading(true);
    const formData = new FormData(form);
    formData.append('delete_notification', 'true');
    fetch('process.php', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
        return response.json();
    })
    .then(data => {
        showAlert('notifications', data.message || (data.success ? 'Notification deleted' : 'Cannot delete active notification'), data.success ? 'success' : 'error');
        if (data.success) {
            const item = form.closest('.notification-item');
            if (item) item.remove();
            if (!document.querySelector('.notification-feed .notification-item')) {
                document.querySelector('.notification-feed').innerHTML = 
                    '<div class="notification-item">No active notifications available</div>';
            }
        }
    })
    .catch(error => {
        console.error('Delete notification error:', error);
        showAlert('notifications', `Failed to delete: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const handleClearAuditLogs = (e) => {
    e.preventDefault();
    if (!confirm('Are you sure you want to clear all audit logs?')) return;
    setLoading(true);
    const form = document.getElementById('clearAllAuditLogsForm');
    if (!form) {
        console.error('Clear audit logs form not found');
        showAlert('activity-log', 'Form not found', 'error');
        setLoading(false);
        return;
    }
    const formData = new FormData(form);
    formData.append('clear_all_audit_logs', 'true');
    fetch('process.php', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
        return response.json();
    })
    .then(data => {
        showAlert('activity-log', data.message || 'Audit logs cleared', data.success ? 'success' : 'error');
        if (data.success) {
            const feed = document.getElementById('activityFeed');
            if (feed) feed.innerHTML = '<div class="activity-item"><div class="activity-details">No recent activity available</div></div>';
        }
    })
    .catch(error => {
        console.error('Clear audit logs error:', error);
        showAlert('activity-log', `Failed to clear logs: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

const updateSelectAllState = () => {
    const selectAll = document.getElementById('select-all');
    const checkboxes = document.querySelectorAll('.item-checkbox:not(#select-all)');
    if (!selectAll || !checkboxes.length) return;
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    const someChecked = Array.from(checkboxes).some(cb => cb.checked);
    selectAll.checked = allChecked;
    selectAll.indeterminate = someChecked && !allChecked;
};

const cancelEdit = () => {
    const form = document.getElementById('item-form');
    const card = document.getElementById('add-edit-form');
    const title = card?.querySelector('h2');
    
    if (!form || !card || !title) {
        console.error('cancelEdit failed: Missing DOM elements', { form: !!form, card: !!card, title: !!title });
        return false;
    }

    form.reset();
    card.classList.remove('edit-mode');
    title.innerHTML = '<i class="fas fa-plus"></i> Add Item Individually';
    form.querySelector('.form-actions').innerHTML = `<button type="submit" name="add_item" class="btn primary"><i class="fas fa-plus"></i> Add Item</button>`;
    const idInput = form.querySelector('input[name="id"]');
    if (idInput) idInput.remove();
    
    console.log('Edit mode cancelled successfully');
    // Temporarily disable persistState to prevent edit mode restoration
    sessionStorage.setItem('inventoryState', JSON.stringify({
        ...JSON.parse(sessionStorage.getItem('inventoryState') || '{}'),
        editMode: false,
        formData: {}
    }));
    return true;
};

const filterActivityLogs = (filter) => {
    setLoading(true);
    const validFilters = ['', 'CREATE', 'UPDATE', 'DELETE'];
    if (!validFilters.includes(filter)) {
        showAlert('activity-log', 'Invalid filter selected', 'error');
        setLoading(false);
        return;
    }
    fetch(`process.php?fetch_activity_logs=true&action_filter=${encodeURIComponent(filter)}&_token=${encodeURIComponent(document.querySelector('meta[name="csrf-token"]').content)}`, {
        method: 'GET',
        headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP error ${response.status}: ${response.statusText}`);
        return response.json();
    })
    .then(data => {
        if (!data.success) throw new Error(data.error || 'Failed to fetch logs');
        const feed = document.getElementById('activityFeed');
        if (feed) {
            feed.innerHTML = data.data.html || '<div class="activity-item"><div class="activity-details">No recent activity available</div></div>';
            showAlert('activity-log', data.message || 'Logs filtered successfully!', 'success');
            persistState();
        } else {
            throw new Error('Activity feed element not found');
        }
    })
    .catch(error => {
        console.error('Filter activity logs error:', error);
        showAlert('activity-log', `Failed to filter logs: ${error.message}`, 'error');
    })
    .finally(() => setLoading(false));
};

// DOM Content Loaded
document.addEventListener('DOMContentLoaded', () => {
    restoreState();
    refreshInventoryTableAndSummary();
    showSessionAlerts();

    document.querySelector('.navbar')?.addEventListener('click', e => {
        const navLink = e.target.closest('.nav-list li a');
        if (navLink) {
            e.preventDefault();
            const sectionId = navLink.dataset.section;
            document.getElementById(sectionId)?.scrollIntoView({ behavior: 'smooth' });
            persistState();
        }
    });

    document.getElementById('item-form')?.addEventListener('submit', handleItemAddUpdate);
    document.getElementById('csvImportForm')?.addEventListener('submit', e => { e.preventDefault(); handleCsvImport(e.target); });
    document.querySelector('form[action="process.php"][enctype="multipart/form-data"]:not(#csvImportForm)')?.addEventListener('submit', e => { e.preventDefault(); handleBatchUpdate(e.target); });
    document.getElementById('bulk-delete-form')?.addEventListener('submit', e => { e.preventDefault(); handleBulkDelete(e.target); });

    document.querySelectorAll('.export-link').forEach(button => {
        button.addEventListener('click', e => handleExportDownload(e, button.dataset.action));
    });

    document.getElementById('clearNotificationsForm')?.addEventListener('submit', handleClearNotifications);
    document.querySelectorAll('.deleteNotificationForm').forEach(form => {
        form.addEventListener('submit', e => { e.preventDefault(); handleDeleteNotification(form); });
    });

    document.getElementById('clearAllAuditLogsForm')?.addEventListener('submit', handleClearAuditLogs);

    const inventoryItems = document.getElementById('inventory-items');
    if (inventoryItems) {
        inventoryItems.addEventListener('click', e => {
            const singleDelete = e.target.closest('.single-delete');
            if (singleDelete) {
                e.preventDefault();
                handleDelete(singleDelete.dataset.id);
            }

            const editLink = e.target.closest('.edit');
            if (editLink) {
                e.preventDefault();
                handleEditClick(editLink.dataset.id);
            }

            const paginationLink = e.target.closest('.pagination-link:not(.disabled)');
            if (paginationLink) {
                e.preventDefault();
                sessionStorage.setItem('currentPage', paginationLink.dataset.page);
                refreshInventoryTableAndSummary();
            }

            const sortLink = e.target.closest('th a');
            if (sortLink) {
                e.preventDefault();
                const sort = sortLink.dataset.sort;
                const currentOrder = sessionStorage.getItem('order') || 'DESC';
                sessionStorage.setItem('sort', sort);
                sessionStorage.setItem('order', currentOrder === 'ASC' ? 'DESC' : 'ASC');
                refreshInventoryTableAndSummary();
            }
        });

        inventoryItems.addEventListener('change', e => {
            if (e.target.id === 'select-all') {
                document.querySelectorAll('.item-checkbox:not(#select-all)').forEach(cb => cb.checked = e.target.checked);
                updateSelectAllState();
            } else if (e.target.classList.contains('item-checkbox')) {
                updateSelectAllState();
            }
        });
    }

    document.getElementById('searchInput')?.addEventListener('input', () => refreshInventoryTableAndSummary());
    document.getElementById('actionFilter')?.addEventListener('change', e => filterActivityLogs(e.target.value));
    document.getElementById('viewAllHistoryBtn')?.addEventListener('click', e => {
        e.preventDefault();
        showAllItemHistory();
    });

    document.querySelector('.btn.primary[onclick="setLoading(true);"]')?.addEventListener('click', e => {
        e.preventDefault();
        setLoading(true);
        fetch(e.target.href, {
            method: 'GET',
            headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json' }
        })
        .then(response => {
            if (!response.ok) return response.text().then(text => { throw new Error(`HTTP error ${response.status}: ${text}`); });
            return response.json();
        })
        .then(data => {
            if (data.success) window.location = 'login.php';
            else showAlert('inventory-items', data.error || 'Logout failed', 'error');
        })
        .catch(error => {
            console.error('Logout error:', error);
            showAlert('inventory-items', `Logout failed: ${error.message}`, 'error');
        })
        .finally(() => setLoading(false));
    });

    window.addEventListener('beforeunload', persistState);
});