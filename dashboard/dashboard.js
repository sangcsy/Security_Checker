let scanData = null;
let checkDefinitions = null;
let filteredResults = [];

document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    loadCheckDefinitions();

    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('autoload') === 'true') {
        setTimeout(() => {
            autoLoadResult();
        }, 500);
    }
});

function initializeEventListeners() {
    const uploadBtn = document.getElementById('uploadBtn');
    const fileInput = document.getElementById('fileInput');
    const uploadBox = document.querySelector('.upload-box');

    uploadBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);

    uploadBox.addEventListener('dragover', handleDragOver);
    uploadBox.addEventListener('drop', handleDrop);

    document.getElementById('statusFilter').addEventListener('change', applyFilters);
    document.getElementById('categoryFilter').addEventListener('change', applyFilters);
    document.getElementById('severityFilter').addEventListener('change', applyFilters);
    document.getElementById('searchInput').addEventListener('input', applyFilters);
    document.getElementById('exportBtn').addEventListener('click', exportToCSV);

    document.querySelector('.modal-close').addEventListener('click', closeModal);
    window.addEventListener('click', (event) => {
        const modal = document.getElementById('detailModal');
        if (event.target === modal) {
            closeModal();
        }
    });
}

async function loadCheckDefinitions() {
    try {
        const response = await fetch('../config/check_definitions.json');
        checkDefinitions = await response.json();
    } catch (error) {
        console.error('Failed to load check definitions:', error);
    }
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        loadJSONFile(file);
    }
}

function handleDragOver(event) {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.add('drag-over');
}

function handleDrop(event) {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.remove('drag-over');

    const files = event.dataTransfer.files;
    if (files.length > 0 && files[0].name.endsWith('.json')) {
        loadJSONFile(files[0]);
    } else {
        alert('JSON 파일만 업로드 가능합니다.');
    }
}

function loadJSONFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            scanData = JSON.parse(event.target.result);
            displayDashboard();
        } catch (error) {
            alert(`JSON 파일을 파싱하는 중 오류가 발생했습니다: ${error.message}`);
        }
    };
    reader.readAsText(file);
}

async function autoLoadResult() {
    try {
        const response = await fetch('/api/result.json');
        if (!response.ok) {
            return;
        }

        const jsonText = await response.text();
        scanData = JSON.parse(jsonText);
        displayDashboard();

        const uploadSection = document.querySelector('.upload-section');
        if (uploadSection) {
            uploadSection.style.display = 'none';
        }

        showNotification('검사 결과가 자동으로 로드되었습니다.', 'success');
    } catch (error) {
        console.error('자동 로드 실패:', error);
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'success' ? '#27AE60' : '#3498DB'};
        color: white;
        border-radius: 5px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

function displayDashboard() {
    if (!scanData) {
        return;
    }

    document.getElementById('metadataSection').style.display = 'block';
    document.getElementById('summarySection').style.display = 'block';
    document.getElementById('filterSection').style.display = 'block';
    document.getElementById('resultsSection').style.display = 'block';

    displayMetadata();
    displaySummary();
    createCharts();
    populateCategoryFilter();

    filteredResults = scanData.results || [];
    displayResultsTable();
}

function displayMetadata() {
    document.getElementById('scanTime').textContent = scanData.metadata?.scan_time || '-';
    document.getElementById('computerName').textContent = scanData.metadata?.computer_name || '-';
    document.getElementById('osVersion').textContent = scanData.metadata?.os_version || '-';
    document.getElementById('totalChecks').textContent = scanData.metadata?.total_checks || '0';
}

function displaySummary() {
    const summary = scanData.summary || {};
    document.getElementById('goodCount').textContent = summary.good || 0;
    document.getElementById('needsManagementCount').textContent = summary.needs_management || 0;
    document.getElementById('manualCheckCount').textContent = summary.manual_check || 0;
    document.getElementById('checkFailedCount').textContent = summary.check_failed || 0;
}

function createCharts() {
    createStatusChart();
    createCategoryChart();
}

function createStatusChart() {
    const ctx = document.getElementById('statusChart').getContext('2d');
    const summary = scanData.summary || {};

    if (window.statusChartInstance) {
        window.statusChartInstance.destroy();
    }

    window.statusChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['양호', '관리 필요', '수동 확인 필요', '점검 불가'],
            datasets: [{
                data: [
                    summary.good || 0,
                    summary.needs_management || 0,
                    summary.manual_check || 0,
                    summary.check_failed || 0
                ],
                backgroundColor: ['#10b981', '#ef4444', '#f59e0b', '#9ca3af'],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total === 0 ? 0 : ((value / total) * 100).toFixed(1);
                            return `${label}: ${value}건 (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

function createCategoryChart() {
    const ctx = document.getElementById('categoryChart').getContext('2d');
    const categoryCounts = {};

    (scanData.results || []).forEach((result) => {
        const category = getCheckCategory(result.item_code);
        categoryCounts[category] = (categoryCounts[category] || 0) + 1;
    });

    const categories = Object.keys(categoryCounts);
    const counts = Object.values(categoryCounts);

    if (window.categoryChartInstance) {
        window.categoryChartInstance.destroy();
    }

    window.categoryChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: categories,
            datasets: [{
                label: '검사 항목 수',
                data: counts,
                backgroundColor: '#3b82f6',
                borderColor: '#2563eb',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label(context) {
                            return `검사 항목: ${context.parsed.y}건`;
                        }
                    }
                }
            }
        }
    });
}

function getCheckCategory(itemCode) {
    if (checkDefinitions && checkDefinitions.checks) {
        const check = checkDefinitions.checks.find((item) => item.item_code === itemCode);
        return check ? check.category : '기타';
    }
    return '기타';
}

function getCheckSeverity(itemCode) {
    if (checkDefinitions && checkDefinitions.checks) {
        const check = checkDefinitions.checks.find((item) => item.item_code === itemCode);
        return check ? check.severity : '-';
    }
    return '-';
}

function getCheckDescription(itemCode) {
    if (checkDefinitions && checkDefinitions.checks) {
        const check = checkDefinitions.checks.find((item) => item.item_code === itemCode);
        return check ? check.description : '-';
    }
    return '-';
}

function populateCategoryFilter() {
    const categoryFilter = document.getElementById('categoryFilter');
    const categories = new Set();

    (scanData.results || []).forEach((result) => {
        categories.add(getCheckCategory(result.item_code));
    });

    categoryFilter.innerHTML = '<option value="all">전체</option>';

    Array.from(categories).sort().forEach((category) => {
        const option = document.createElement('option');
        option.value = category;
        option.textContent = category;
        categoryFilter.appendChild(option);
    });
}

function applyFilters() {
    const statusFilter = document.getElementById('statusFilter').value;
    const categoryFilter = document.getElementById('categoryFilter').value;
    const severityFilter = document.getElementById('severityFilter').value;
    const searchQuery = document.getElementById('searchInput').value.toLowerCase();

    filteredResults = (scanData.results || []).filter((result) => {
        const normalizedStatus = normalizeStatus(result.status);

        if (statusFilter !== 'all' && normalizedStatus !== statusFilter) {
            return false;
        }

        const category = getCheckCategory(result.item_code);
        if (categoryFilter !== 'all' && category !== categoryFilter) {
            return false;
        }

        const severity = getCheckSeverity(result.item_code);
        if (severityFilter !== 'all' && severity !== severityFilter) {
            return false;
        }

        if (searchQuery) {
            const searchText = `${result.item_code} ${result.check_title} ${result.current_state}`.toLowerCase();
            if (!searchText.includes(searchQuery)) {
                return false;
            }
        }

        return true;
    });

    displayResultsTable();
}

function displayResultsTable() {
    const tbody = document.getElementById('resultsTableBody');
    tbody.innerHTML = '';
    document.getElementById('displayedCount').textContent = filteredResults.length;

    filteredResults.forEach((result) => {
        const row = document.createElement('tr');
        row.className = `status-${getStatusClass(result.status)}`;

        const category = getCheckCategory(result.item_code);
        const severity = getCheckSeverity(result.item_code);

        row.innerHTML = `
            <td><strong>${result.item_code}</strong></td>
            <td>${category}</td>
            <td>${result.check_title}</td>
            <td><span class="status-badge ${getStatusClass(result.status)}">${normalizeStatus(result.status)}</span></td>
            <td><span class="severity-badge severity-${severity}">${severity}</span></td>
            <td class="current-state">${truncateText(result.current_state || '', 50)}</td>
            <td><button class="detail-btn" onclick="showDetail('${result.item_code}')">상세보기</button></td>
        `;

        tbody.appendChild(row);
    });
}

function getStatusClass(status) {
    const statusMap = {
        '양호': 'good',
        '관리 필요': 'danger',
        '수동 확인 필요': 'warning',
        '점검 불가': 'disabled'
    };
    return statusMap[status] || 'default';
}

function normalizeStatus(status) {
    return status;
}

function truncateText(text, maxLength) {
    if (text.length <= maxLength) {
        return text;
    }
    return text.substring(0, maxLength) + '...';
}

function showDetail(itemCode) {
    const result = (scanData.results || []).find((item) => item.item_code === itemCode);
    if (!result) {
        return;
    }

    document.getElementById('modalItemCode').textContent = result.item_code;
    document.getElementById('modalCheckTitle').textContent = result.check_title;
    document.getElementById('modalCategory').textContent = getCheckCategory(itemCode);
    document.getElementById('modalStatus').textContent = normalizeStatus(result.status);
    document.getElementById('modalStatus').className = `status-badge ${getStatusClass(result.status)}`;
    document.getElementById('modalSeverity').textContent = getCheckSeverity(itemCode);
    document.getElementById('modalCurrentState').textContent = result.current_state;
    document.getElementById('modalExpectedState').textContent = result.expected_state;
    document.getElementById('modalOperationalMeaning').textContent = result.operational_meaning;
    document.getElementById('modalDescription').textContent = getCheckDescription(itemCode);

    document.getElementById('detailModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('detailModal').style.display = 'none';
}

function exportToCSV() {
    const headers = ['코드', '카테고리', '검사 항목', '상태', '심각도', '현재 상태', '권장 상태', '운영 의미'];
    const rows = filteredResults.map((result) => [
        result.item_code,
        getCheckCategory(result.item_code),
        result.check_title,
        result.status,
        getCheckSeverity(result.item_code),
        result.current_state,
        result.expected_state,
        result.operational_meaning
    ]);

    let csvContent = '\uFEFF';
    csvContent += headers.join(',') + '\n';

    rows.forEach((row) => {
        const escapedRow = row.map((cell) => {
            const value = String(cell ?? '').replace(/"/g, '""');
            return `"${value}"`;
        });
        csvContent += escapedRow.join(',') + '\n';
    });

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);

    link.setAttribute('href', url);
    link.setAttribute('download', `security_report_${timestamp}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
