/**
 * PhishGuard Dashboard Charts
 *
 * Area chart with gradient fills for threat trends
 * and doughnut chart for threat distribution.
 */
(function () {
    'use strict';

    var levelData = window.__pgDashboard.levelData;
    var trendData = window.__pgDashboard.trendData;
    var period = window.__pgDashboard.period || 30;

    // --- Build trend data ---
    var dayMap = {};
    trendData.forEach(function (row) {
        if (!dayMap[row.day]) dayMap[row.day] = { critical: 0, high: 0, medium: 0, low: 0, clean: 0 };
        dayMap[row.day][row.threat_level] = row.cnt;
    });

    var days = Object.keys(dayMap).sort();
    var critData = days.map(function (d) { return dayMap[d].critical || 0; });
    var highData = days.map(function (d) { return dayMap[d].high || 0; });
    var medData = days.map(function (d) { return dayMap[d].medium || 0; });
    var lowCleanData = days.map(function (d) { return (dayMap[d].low || 0) + (dayMap[d].clean || 0); });

    var dayLabels = days.map(function (d) {
        var parts = d.split('-');
        return parts[1] + '/' + parts[2];
    });

    // --- Trend Area Chart ---
    var trendCtx = document.getElementById('trendChart');
    if (trendCtx) {
        var ctx = trendCtx.getContext('2d');

        // Create gradients
        var critGrad = ctx.createLinearGradient(0, 0, 0, 260);
        critGrad.addColorStop(0, 'rgba(220,38,38,0.45)');
        critGrad.addColorStop(1, 'rgba(220,38,38,0.02)');

        var highGrad = ctx.createLinearGradient(0, 0, 0, 260);
        highGrad.addColorStop(0, 'rgba(234,88,12,0.40)');
        highGrad.addColorStop(1, 'rgba(234,88,12,0.02)');

        var medGrad = ctx.createLinearGradient(0, 0, 0, 260);
        medGrad.addColorStop(0, 'rgba(202,138,4,0.35)');
        medGrad.addColorStop(1, 'rgba(202,138,4,0.02)');

        var lowGrad = ctx.createLinearGradient(0, 0, 0, 260);
        lowGrad.addColorStop(0, 'rgba(34,163,72,0.25)');
        lowGrad.addColorStop(1, 'rgba(34,163,72,0.02)');

        new Chart(ctx, {
            type: 'line',
            data: {
                labels: dayLabels,
                datasets: [
                    {
                        label: 'Critical',
                        data: critData,
                        borderColor: 'rgba(220,38,38,0.9)',
                        backgroundColor: critGrad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 1,
                        pointHoverRadius: 4,
                        order: 1,
                    },
                    {
                        label: 'High',
                        data: highData,
                        borderColor: 'rgba(234,88,12,0.9)',
                        backgroundColor: highGrad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 1,
                        pointHoverRadius: 4,
                        order: 2,
                    },
                    {
                        label: 'Medium',
                        data: medData,
                        borderColor: 'rgba(202,138,4,0.8)',
                        backgroundColor: medGrad,
                        borderWidth: 1.5,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 0,
                        pointHoverRadius: 3,
                        order: 3,
                    },
                    {
                        label: 'Low/Clean',
                        data: lowCleanData,
                        borderColor: 'rgba(34,163,72,0.6)',
                        backgroundColor: lowGrad,
                        borderWidth: 1,
                        fill: true,
                        tension: 0.35,
                        pointRadius: 0,
                        pointHoverRadius: 3,
                        order: 4,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                scales: {
                    x: {
                        ticks: { color: '#6e7681', maxRotation: 0, maxTicksLimit: period <= 7 ? 7 : 10, font: { size: 10, family: "'Space Grotesk', sans-serif" } },
                        grid: { color: 'rgba(28,35,51,0.5)', drawBorder: false },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: '#6e7681', stepSize: 1, font: { size: 10, family: "'Space Grotesk', sans-serif" } },
                        grid: { color: 'rgba(28,35,51,0.5)', drawBorder: false },
                    },
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#c9d1d9', font: { size: 10, family: "'Space Grotesk', sans-serif" }, boxWidth: 12, padding: 14 },
                    },
                    tooltip: {
                        backgroundColor: '#151a26',
                        titleColor: '#c9d1d9',
                        bodyColor: '#c9d1d9',
                        borderColor: '#1c2333',
                        borderWidth: 1,
                        padding: 10,
                        titleFont: { family: "'Space Grotesk', sans-serif" },
                        bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
                    },
                },
            },
        });
    }

    // --- Threat Distribution Doughnut ---
    var pieCtx = document.getElementById('threatPieChart');
    if (pieCtx) {
        new Chart(pieCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Clean'],
                datasets: [{
                    data: [
                        levelData.critical || 0,
                        levelData.high || 0,
                        levelData.medium || 0,
                        levelData.low || 0,
                        levelData.clean || 0,
                    ],
                    backgroundColor: [
                        'rgba(220,38,38,0.85)',
                        'rgba(234,88,12,0.85)',
                        'rgba(202,138,4,0.7)',
                        'rgba(34,163,72,0.6)',
                        'rgba(22,130,52,0.5)',
                    ],
                    borderColor: '#0d1017',
                    borderWidth: 2,
                    hoverOffset: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '62%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#c9d1d9', font: { size: 10, family: "'Space Grotesk', sans-serif" }, boxWidth: 12, padding: 14 },
                    },
                    tooltip: {
                        backgroundColor: '#151a26',
                        titleColor: '#c9d1d9',
                        bodyColor: '#c9d1d9',
                        borderColor: '#1c2333',
                        borderWidth: 1,
                        padding: 10,
                    },
                },
            },
        });
    }
})();
