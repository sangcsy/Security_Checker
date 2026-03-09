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
    document.getElementById('reportBtn').addEventListener('click', exportToReport);

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
        alert('\u004a\u0053\u004f\u004e \uD30C\uC77C\uB9CC \uC5C5\uB85C\uB4DC \uAC00\uB2A5\uD569\uB2C8\uB2E4.');
    }
}

function loadJSONFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            scanData = JSON.parse(event.target.result);
            displayDashboard();
        } catch (error) {
            alert(`\u004a\u0053\u004f\u004e \uD30C\uC77C\uC744 \uD30C\uC2F1\uD558\uB294 \uC911 \uC624\uB958\uAC00 \uBC1C\uC0DD\uD588\uC2B5\uB2C8\uB2E4: ${error.message}`);
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

        showNotification('\uAC80\uC0AC \uACB0\uACFC\uAC00 \uC790\uB3D9\uC73C\uB85C \uB85C\uB4DC\uB418\uC5C8\uC2B5\uB2C8\uB2E4.', 'success');
    } catch (error) {
        console.error('\uC790\uB3D9 \uB85C\uB4DC \uC2E4\uD328:', error);
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
            labels: ['\uC591\uD638', '\uAD00\uB9AC \uD544\uC694', '\uC218\uB3D9 \uD655\uC778 \uD544\uC694', '\uC810\uAC80 \uBD88\uAC00'],
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
                            return `${label}: ${value}\uAC74 (${percentage}%)`;
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
                label: '\uAC80\uC0AC \uD56D\uBAA9 \uC218',
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
                            return `\uAC80\uC0AC \uD56D\uBAA9: ${context.parsed.y}\uAC74`;
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
        return check ? check.category : '\uAE30\uD0C0';
    }
    return '\uAE30\uD0C0';
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

    categoryFilter.innerHTML = '<option value="all">\uC804\uCCB4</option>';

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
        const severity = normalizeSeverity(getCheckSeverity(result.item_code));

        row.innerHTML = `
            <td><strong>${result.item_code}</strong></td>
            <td>${category}</td>
            <td>${result.check_title}</td>
            <td><span class="status-badge ${getStatusClass(result.status)}">${normalizeStatus(result.status)}</span></td>
            <td><span class="severity-badge severity-${getSeverityClass(severity)}">${severity}</span></td>
            <td class="current-state">${truncateText(result.current_state || '', 50)}</td>
            <td><button class="detail-btn" onclick="showDetail('${result.item_code}')">\uC0C1\uC138\uBCF4\uAE30</button></td>
        `;

        tbody.appendChild(row);
    });
}

function getStatusClass(status) {
    const normalized = normalizeStatus(status);
    const statusMap = {
        '\uC591\uD638': 'good',
        '\uAD00\uB9AC \uD544\uC694': 'danger',
        '\uC218\uB3D9 \uD655\uC778 \uD544\uC694': 'warning',
        '\uC810\uAC80 \uBD88\uAC00': 'disabled'
    };
    return statusMap[normalized] || 'default';
}

function normalizeStatus(status) {
    const value = String(status ?? '').trim();
    const aliases = {
        '?묓샇': '\uC591\uD638',
        '양호': '\uC591\uD638',
        'good': '\uC591\uD638',
        'GOOD': '\uC591\uD638',
        '愿由??꾩슂': '\uAD00\uB9AC \uD544\uC694',
        '관리 필요': '\uAD00\uB9AC \uD544\uC694',
        'needs_management': '\uAD00\uB9AC \uD544\uC694',
        '?섎룞 ?뺤씤 ?꾩슂': '\uC218\uB3D9 \uD655\uC778 \uD544\uC694',
        '수동 확인 필요': '\uC218\uB3D9 \uD655\uC778 \uD544\uC694',
        'manual_check': '\uC218\uB3D9 \uD655\uC778 \uD544\uC694',
        '?먭? 遺덇?': '\uC810\uAC80 \uBD88\uAC00',
        '점검 불가': '\uC810\uAC80 \uBD88\uAC00',
        'check_failed': '\uC810\uAC80 \uBD88\uAC00'
    };
    return aliases[value] || value || '-';
}

function normalizeSeverity(severity) {
    const value = String(severity ?? '').trim();
    const aliases = {
        '상': '\uC0C1',
        '??': '\uC0C1',
        '중': '\uC911',
        '以?': '\uC911',
        '하': '\uD558'
    };
    return aliases[value] || value || '-';
}

function getSeverityClass(severity) {
    const normalized = normalizeSeverity(severity);
    const classMap = {
        '\uC0C1': 'high',
        '\uC911': 'medium',
        '\uD558': 'low'
    };
    return classMap[normalized] || 'unknown';
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
    document.getElementById('modalSeverity').textContent = normalizeSeverity(getCheckSeverity(itemCode));
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
    const headers = ['\uCF54\uB4DC', '\uCE74\uD14C\uACE0\uB9AC', '\uAC80\uC0AC \uD56D\uBAA9', '\uC0C1\uD0DC', '\uC2EC\uAC01\uB3C4', '\uD604\uC7AC \uC0C1\uD0DC', '\uAD8C\uC7A5 \uC0C1\uD0DC', '\uC6B4\uC601 \uC758\uBBF8'];
    const rows = filteredResults.map((result) => [
        result.item_code,
        getCheckCategory(result.item_code),
        result.check_title,
        normalizeStatus(result.status),
        normalizeSeverity(getCheckSeverity(result.item_code)),
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

function exportToReport() {
    if (!scanData || !filteredResults.length) {
        alert('\uB2E4\uC6B4\uB85C\uB4DC\uD560 \uBCF4\uACE0\uC11C \uB370\uC774\uD130\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4.');
        return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
    const reportHtml = buildReportHtml();
    const blob = new Blob([reportHtml], { type: 'text/html;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', `security_report_${timestamp}.html`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => {
        URL.revokeObjectURL(url);
    }, 1000);
}

function buildReportHtml() {
    const summary = scanData.summary || {};
    const metadata = scanData.metadata || {};
    const generatedAt = new Date().toLocaleString('ko-KR');
    const categories = buildCategorySummary(filteredResults);
    const priorityItems = filteredResults.filter((item) => {
        const status = normalizeStatus(item.status);
        const severity = normalizeSeverity(getCheckSeverity(item.item_code));
        return status !== '\uC591\uD638' && (status === '\uAD00\uB9AC \uD544\uC694' || status === '\uC218\uB3D9 \uD655\uC778 \uD544\uC694' || status === '\uC810\uAC80 \uBD88\uAC00');
    }).sort((a, b) => {
        const statusRank = {
            '\uAD00\uB9AC \uD544\uC694': 0,
            '\uC218\uB3D9 \uD655\uC778 \uD544\uC694': 1,
            '\uC810\uAC80 \uBD88\uAC00': 2
        };
        const severityRank = {
            '\uC0C1': 0,
            '\uC911': 1,
            '\uD558': 2,
            '-': 3
        };

        const statusDiff = (statusRank[normalizeStatus(a.status)] ?? 9) - (statusRank[normalizeStatus(b.status)] ?? 9);
        if (statusDiff !== 0) {
            return statusDiff;
        }

        const severityDiff = (severityRank[normalizeSeverity(getCheckSeverity(a.item_code))] ?? 9) - (severityRank[normalizeSeverity(getCheckSeverity(b.item_code))] ?? 9);
        if (severityDiff !== 0) {
            return severityDiff;
        }

        return String(a.item_code).localeCompare(String(b.item_code));
    }).slice(0, 8);

    const cards = [
        { label: '\uC591\uD638', value: summary.good || 0, tone: 'good' },
        { label: '\uAD00\uB9AC \uD544\uC694', value: summary.needs_management || 0, tone: 'danger' },
        { label: '\uC218\uB3D9 \uD655\uC778 \uD544\uC694', value: summary.manual_check || 0, tone: 'warning' },
        { label: '\uC810\uAC80 \uBD88\uAC00', value: summary.check_failed || 0, tone: 'muted' }
    ];

    const detailRows = filteredResults.map((result) => `
            <tr>
                <td class="cell-code">${escapeHtml(result.item_code)}</td>
                <td class="cell-category">${escapeHtml(getCheckCategory(result.item_code))}</td>
                <td class="cell-title">${escapeHtml(result.check_title || '-')}</td>
                <td class="cell-status"><span class="status-pill ${getStatusClass(result.status)}">${escapeHtml(normalizeStatus(result.status))}</span></td>
                <td class="cell-severity"><span class="severity-pill severity-${getSeverityClass(getCheckSeverity(result.item_code))}">${escapeHtml(normalizeSeverity(getCheckSeverity(result.item_code)))}</span></td>
                <td class="cell-state">${escapeHtml(result.current_state || '-')}</td>
                <td class="cell-state">${escapeHtml(result.expected_state || '-')}</td>
            </tr>
        `).join('');

    const categoryRows = categories.map((item) => `
            <tr>
                <td>${escapeHtml(item.category)}</td>
                <td>${item.count}</td>
            </tr>
        `).join('');

    const priorityRows = priorityItems.length
        ? priorityItems.map((item) => `
            <tr>
                <td class="cell-code">${escapeHtml(item.item_code)}</td>
                <td class="cell-title">${escapeHtml(item.check_title || '-')}</td>
                <td class="cell-status"><span class="status-pill ${getStatusClass(item.status)}">${escapeHtml(normalizeStatus(item.status))}</span></td>
                <td class="cell-severity"><span class="severity-pill severity-${getSeverityClass(getCheckSeverity(item.item_code))}">${escapeHtml(normalizeSeverity(getCheckSeverity(item.item_code)))}</span></td>
                <td class="cell-state">${escapeHtml(item.operational_meaning || '-')}</td>
            </tr>
        `).join('')
        : '<tr><td colspan="5">\uC6B0\uC120 \uC870\uCE58\uAC00 \uD544\uC694\uD55C \uD56D\uBAA9\uC774 \uC5C6\uC2B5\uB2C8\uB2E4.</td></tr>';

    const summaryCards = cards.map((card) => `
            <div class="summary-card ${card.tone}">
                <span>${card.label}</span>
                <strong>${card.value}</strong>
            </div>
        `).join('');

    return `<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>\uBCF4\uC548 \uC810\uAC80 \uBCF4\uACE0\uC11C</title>
    <style>
        :root {
            --ink: #10233b;
            --subtle: #5b6b80;
            --line: #d7e1ec;
            --panel: #ffffff;
            --good: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --muted: #94a3b8;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            padding: 32px;
            color: var(--ink);
            font-family: 'Malgun Gothic', 'Noto Sans KR', sans-serif;
            background: linear-gradient(180deg, #edf4ff 0%, #f8fbff 48%, #eef7f2 100%);
        }
        .report-shell {
            max-width: 1180px;
            margin: 0 auto;
        }
        .hero {
            padding: 34px 38px;
            color: #ffffff;
            border-radius: 28px;
            background: linear-gradient(135deg, #163b68 0%, #2356a5 48%, #0f766e 100%);
            box-shadow: 0 22px 54px rgba(16, 35, 59, 0.18);
        }
        .hero h1 {
            margin: 0 0 10px;
            font-size: 34px;
        }
        .hero p {
            margin: 0;
            color: rgba(255, 255, 255, 0.82);
        }
        .meta-grid, .summary-grid {
            display: grid;
            gap: 14px;
            margin-top: 22px;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        }
        .meta-card, .summary-card, .section {
            background: #ffffff;
            border: 1px solid rgba(215, 225, 236, 0.9);
            border-radius: 22px;
            box-shadow: 0 18px 38px rgba(15, 23, 42, 0.06);
        }
        .meta-card, .summary-card {
            padding: 20px 22px;
        }
        .meta-card span, .summary-card span, .section-head p {
            display: block;
            color: var(--subtle);
            font-size: 13px;
        }
        .meta-card strong, .summary-card strong {
            display: block;
            margin-top: 8px;
            font-size: 22px;
            color: var(--ink);
        }
        .summary-card.good strong { color: var(--good); }
        .summary-card.danger strong { color: var(--danger); }
        .summary-card.warning strong { color: var(--warning); }
        .summary-card.muted strong { color: var(--muted); }
        .report-grid {
            display: grid;
            grid-template-columns: 1.15fr 0.85fr;
            gap: 18px;
            margin-top: 22px;
        }
        .section {
            margin-top: 22px;
            padding: 24px;
        }
        .section-head {
            margin-bottom: 16px;
        }
        .section h2 {
            margin: 0 0 6px;
            font-size: 22px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            table-layout: fixed;
        }
        th, td {
            padding: 12px 10px;
            text-align: left;
            vertical-align: top;
            border-bottom: 1px solid var(--line);
            color: var(--ink);
            overflow-wrap: anywhere;
            word-break: keep-all;
        }
        th {
            color: #314155;
            font-size: 12px;
            letter-spacing: 0.04em;
            text-transform: none;
            background: #f6f9fc;
        }
        .status-pill {
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            color: #ffffff;
            font-size: 12px;
            font-weight: 700;
        }
        .status-pill.good { background: var(--good); }
        .status-pill.danger { background: var(--danger); }
        .status-pill.warning { background: var(--warning); }
        .status-pill.disabled, .status-pill.default { background: var(--muted); }
        .severity-pill {
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            color: #0f172a;
        }
        .severity-pill.severity-high { background: #fee2e2; color: #b91c1c; }
        .severity-pill.severity-medium { background: #fef3c7; color: #92400e; }
        .severity-pill.severity-low { background: #dbeafe; color: #1d4ed8; }
        .severity-pill.severity-unknown { background: #e5e7eb; color: #475569; }
        .cell-code { width: 10%; white-space: nowrap; font-weight: 700; }
        .cell-category { width: 13%; }
        .cell-status { width: 14%; text-align: center; }
        .cell-severity { width: 10%; text-align: center; }
        .cell-title { width: 22%; }
        .cell-state { width: 22%; line-height: 1.55; }
        .footer {
            margin-top: 22px;
            color: var(--subtle);
            font-size: 12px;
            text-align: right;
        }
        @media (max-width: 900px) {
            body { padding: 18px; }
            .hero { padding: 26px; }
            .report-grid { grid-template-columns: 1fr; }
        }
        @media print {
            body {
                padding: 0;
                background: #ffffff;
            }
            .hero, .meta-card, .summary-card, .section {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="report-shell">
        <section class="hero">
            <h1>\uBCF4\uC548 \uC810\uAC80 \uACB0\uACFC \uBCF4\uACE0\uC11C</h1>
            <p>${escapeHtml(metadata.computer_name || '-')} \uC2DC\uC2A4\uD15C\uC758 \uC810\uAC80 \uACB0\uACFC\uB97C \uC815\uB9AC\uD55C \uB2E4\uC6B4\uB85C\uB4DC\uC6A9 \uBCF4\uACE0\uC11C\uC785\uB2C8\uB2E4.</p>
            <div class="meta-grid">
                <div class="meta-card"><span>\uC0DD\uC131 \uC2DC\uAC01</span><strong>${escapeHtml(generatedAt)}</strong></div>
                <div class="meta-card"><span>\uC810\uAC80 \uC2DC\uAC01</span><strong>${escapeHtml(metadata.scan_time || '-')}</strong></div>
                <div class="meta-card"><span>\uB300\uC0C1 \uC2DC\uC2A4\uD15C</span><strong>${escapeHtml(metadata.computer_name || '-')}</strong></div>
                <div class="meta-card"><span>\uC6B4\uC601\uCCB4\uC81C</span><strong>${escapeHtml(metadata.os_version || '-')}</strong></div>
            </div>
        </section>
        <section class="summary-grid">${summaryCards}</section>
        <section class="report-grid">
            <div class="section">
                <div class="section-head">
                    <h2>\uC6B0\uC120 \uC870\uCE58 \uD56D\uBAA9</h2>
                    <p>\uC591\uD638\uB97C \uC81C\uC678\uD55C \uD56D\uBAA9 \uC911\uC5D0\uC11C \uAD00\uB9AC \uD544\uC694, \uC218\uB3D9 \uD655\uC778 \uD544\uC694, \uC810\uAC80 \uBD88\uAC00 \uC21C\uC73C\uB85C \uC6B0\uC120 \uC815\uB82C\uD588\uC2B5\uB2C8\uB2E4.</p>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>\uCF54\uB4DC</th>
                            <th>\uC810\uAC80 \uD56D\uBAA9</th>
                            <th>\uC0C1\uD0DC</th>
                            <th>\uC2EC\uAC01\uB3C4</th>
                            <th>\uC6B4\uC601 \uC758\uBBF8</th>
                        </tr>
                    </thead>
                    <tbody>${priorityRows}</tbody>
                </table>
            </div>
            <div class="section">
                <div class="section-head">
                    <h2>\uCE74\uD14C\uACE0\uB9AC \uBD84\uD3EC</h2>
                    <p>\uD604\uC7AC \uD544\uD130 \uAE30\uC900\uC73C\uB85C \uC9D1\uACC4\uB41C \uD56D\uBAA9 \uC218\uC785\uB2C8\uB2E4.</p>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>\uCE74\uD14C\uACE0\uB9AC</th>
                            <th>\uD56D\uBAA9 \uC218</th>
                        </tr>
                    </thead>
                    <tbody>${categoryRows}</tbody>
                </table>
            </div>
        </section>
        <section class="section">
            <div class="section-head">
                <h2>\uC0C1\uC138 \uC810\uAC80 \uACB0\uACFC</h2>
                <p>\uB300\uC2DC\uBCF4\uB4DC\uC5D0\uC11C \uC801\uC6A9\uD55C \uD544\uD130 \uACB0\uACFC \uADF8\uB300\uB85C \uD3EC\uD568\uB429\uB2C8\uB2E4.</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>\uCF54\uB4DC</th>
                        <th>\uCE74\uD14C\uACE0\uB9AC</th>
                        <th>\uC810\uAC80 \uD56D\uBAA9</th>
                        <th>\uC0C1\uD0DC</th>
                        <th>\uC2EC\uAC01\uB3C4</th>
                        <th>\uD604\uC7AC \uC0C1\uD0DC</th>
                        <th>\uAD8C\uC7A5 \uC0C1\uD0DC</th>
                    </tr>
                </thead>
                <tbody>${detailRows}</tbody>
            </table>
        </section>
        <div class="footer">\uD544\uD130 \uC801\uC6A9 \uACB0\uACFC ${filteredResults.length}\uAC74 \uD3EC\uD568</div>
    </div>
</body>
</html>`;
}

function buildCategorySummary(results) {
    const counts = new Map();

    results.forEach((result) => {
        const category = getCheckCategory(result.item_code);
        counts.set(category, (counts.get(category) || 0) + 1);
    });

    return Array.from(counts.entries())
        .map(([category, count]) => ({ category, count }))
        .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
