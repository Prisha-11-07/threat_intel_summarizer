/**
 * CyberSentinel Frontend Application Controller.
 * Handles PDF uploads, sample loading, dynamic UI rendering,
 * defanging/refanging switching, STIX visualization, and firewall rule exporting.
 */

// Global State
let currentReportData = null;
let showDefanged = true;
let currentTypeFilter = 'all';
let currentFirewallTab = 'suricata';

// DOM Elements
const fileInput = document.getElementById('fileInput');
const dropzone = document.getElementById('dropzone');
const loadingIndicator = document.getElementById('loadingIndicator');
const progressBar = document.getElementById('progressBar');
const loadingStepText = document.getElementById('loadingStepText');
const loadingPercent = document.getElementById('loadingPercent');
const dashboardSection = document.getElementById('dashboardSection');

// Initialize event listeners
document.addEventListener('DOMContentLoaded', () => {
    setupDropzone();
    // Preload default sample report on startup for instant demo capability
    loadSample('cisa-volt-typhoon');
});

function setupDropzone() {
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.add('border-cyan-400', 'bg-slate-900/80');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.remove('border-cyan-400', 'bg-slate-900/80');
        }, false);
    });

    dropzone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0 && files[0].name.toLowerCase().endsWith('.pdf')) {
            uploadFile(files[0]);
        } else {
            showToast('Please drop a valid PDF report', true);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (fileInput.files.length > 0) {
            uploadFile(fileInput.files[0]);
        }
    });
}

function showLoading(stepMsg, percent) {
    loadingIndicator.classList.remove('hidden');
    loadingStepText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> ${stepMsg}`;
    loadingPercent.textContent = `${percent}%`;
    progressBar.style.width = `${percent}%`;
}

function hideLoading() {
    loadingIndicator.classList.add('hidden');
}

async function uploadFile(file) {
    showLoading('Ingesting multi-page PDF document...', 20);
    const formData = new FormData();
    formData.append('file', file);

    try {
        setTimeout(() => showLoading('Executing Named Entity Recognition and defanging engine...', 50), 300);
        setTimeout(() => showLoading('Synthesizing MITRE ATT&CK and STIX 2.1 schemas...', 80), 600);

        const response = await fetch('/api/analyze-pdf', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Analysis failed');
        }

        const data = await response.json();
        renderDashboard(data);
        showToast(`Successfully analyzed: ${file.name}`);
    } catch (err) {
        console.error(err);
        showToast(`Error: ${err.message}`, true);
    } finally {
        hideLoading();
    }
}

async function loadSample(sampleId) {
    showLoading(`Loading preloaded vendor advisory: ${sampleId}...`, 30);
    try {
        setTimeout(() => showLoading('Extracting living-off-the-land techniques and IoCs...', 65), 250);

        const response = await fetch(`/api/analyze-sample/${sampleId}`, {
            method: 'POST'
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Sample load failed');
        }

        const data = await response.json();
        renderDashboard(data);
        showToast(`Loaded ${data.vendor} Intelligence Report`);
    } catch (err) {
        console.error(err);
        showToast(`Failed to load sample: ${err.message}`, true);
    } finally {
        hideLoading();
    }
}

function renderDashboard(data) {
    currentReportData = data;
    dashboardSection.classList.remove('hidden');

    const analysis = data.analysis;
    const actor = analysis.threat_actor;

    // 1. Top Metrics
    document.getElementById('actorName').textContent = actor.name || 'Unattributed Threat';
    document.getElementById('actorOrigin').textContent = actor.origin || 'Unknown Origin';

    const aliasesContainer = document.getElementById('actorAliases');
    aliasesContainer.innerHTML = '';
    (actor.aliases || []).slice(0, 3).forEach(alias => {
        const span = document.createElement('span');
        span.className = 'text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700';
        span.textContent = alias;
        aliasesContainer.appendChild(span);
    });

    // Severity & Risk
    const severityBadge = document.getElementById('severityBadge');
    const severity = analysis.severity || 'UNKNOWN';
    severityBadge.innerHTML = `<span class="w-2 h-2 rounded-full ${severity === 'CRITICAL' ? 'bg-red-500 animate-ping' : severity === 'UNKNOWN' ? 'bg-slate-500' : 'bg-amber-500'}"></span> ${severity}`;
    if (severity === 'CRITICAL') {
        severityBadge.className = 'px-3 py-1 rounded-md text-xs font-bold font-mono uppercase tracking-wider bg-red-950/80 text-red-400 border border-red-800 flex items-center gap-1.5';
    } else if (severity === 'UNKNOWN') {
        severityBadge.className = 'px-3 py-1 rounded-md text-xs font-bold font-mono uppercase tracking-wider bg-slate-900 text-slate-400 border border-slate-700 flex items-center gap-1.5';
    } else {
        severityBadge.className = 'px-3 py-1 rounded-md text-xs font-bold font-mono uppercase tracking-wider bg-amber-950/80 text-amber-400 border border-amber-800 flex items-center gap-1.5';
    }
    document.getElementById('riskScore').textContent = Number.isFinite(Number(analysis.risk_score)) ? analysis.risk_score : '—';
    document.getElementById('riskFactors').textContent = (analysis.risk_factors || []).map(factor => `${factor.factor}: +${factor.points}`).join(' | ') || 'No scored evidence';
    document.querySelector('#killChainGrid')?.previousElementSibling?.querySelector('span:last-child')?.replaceChildren(document.createTextNode(`${(analysis.kill_chain || []).length} Stages Tracked`));
    document.getElementById('analysisStatus').textContent = analysis.analysis_status === 'completed'
        ? 'GenAI analysis completed from uploaded report evidence'
        : `GenAI analysis unavailable: ${analysis.analysis_error || 'No provider result returned'}`;

    // IoC Totals
    document.getElementById('totalIoCs').textContent = data.iocs.length;
    const breakdown = data.ioc_breakdown || {};
    document.getElementById('statIps').textContent = (breakdown.ipv4 || 0) + (breakdown.ipv6 || 0);
    document.getElementById('statDomains').textContent = (breakdown.domain || 0) + (breakdown.url || 0);
    document.getElementById('statHashes').textContent = (breakdown.sha256 || 0) + (breakdown.md5 || 0);

    // Vendor & Provenance
    document.getElementById('vendorName').textContent = data.vendor || 'Threat Intel Advisory';
    document.getElementById('totalPages').textContent = `${data.total_pages} Pages Analyzed`;
    document.getElementById('tlpBadge').textContent = data.tlp || 'TLP:CLEAR';

    // 2. Executive Summary
    document.getElementById('execSummaryText').textContent = analysis.executive_summary;

    // 3. Tactical Action Items
    const tacticalList = document.getElementById('tacticalList');
    tacticalList.innerHTML = '';
    (analysis.tactical_recommendations || []).forEach(item => {
        const div = document.createElement('div');
        div.className = 'p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start justify-between gap-3 text-xs';
        div.innerHTML = `
            <div>
                <span class="font-semibold text-slate-200 block">${item.category}</span>
                <span class="text-slate-400 text-[11px]">${item.action}</span>
            </div>
            <span class="px-2 py-0.5 rounded font-mono text-[10px] font-bold shrink-0 ${item.priority.includes('P1') ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}">
                ${item.priority}
            </span>
        `;
        tacticalList.appendChild(div);
    });

    // 4. Targeted Sectors & Malware
    const sectorsList = document.getElementById('sectorsList');
    sectorsList.innerHTML = '';
    (analysis.targeted_sectors || []).forEach(s => {
        const span = document.createElement('span');
        span.className = 'px-2.5 py-1 rounded-md text-xs font-mono bg-red-950/40 text-red-300 border border-red-900/60 flex items-center gap-1.5';
        span.innerHTML = `<i class="fa-solid fa-bullseye text-[10px] text-red-400"></i> ${s}`;
        sectorsList.appendChild(span);
    });

    const malwareList = document.getElementById('malwareList');
    malwareList.innerHTML = '';
    (analysis.malware_families || []).forEach(m => {
        const span = document.createElement('span');
        span.className = 'px-2.5 py-1 rounded-md text-xs font-mono bg-amber-950/40 text-amber-300 border border-amber-900/60 flex items-center gap-1.5';
        span.innerHTML = `<i class="fa-solid fa-bug text-[10px] text-amber-400"></i> ${m}`;
        malwareList.appendChild(span);
    });

    const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
    vulnerabilitiesList.innerHTML = '';
    (analysis.vulnerabilities || []).forEach(vulnerability => {
        const item = document.createElement('div');
        const id = typeof vulnerability === 'string' ? vulnerability : vulnerability.id;
        const description = typeof vulnerability === 'string' ? '' : vulnerability.description;
        item.innerHTML = `<span class="text-red-300 font-mono">${escapeHtml(id || 'Unspecified')}</span>${description ? ` <span>${escapeHtml(description)}</span>` : ''}`;
        vulnerabilitiesList.appendChild(item);
    });
    if (!vulnerabilitiesList.children.length) {
        vulnerabilitiesList.textContent = 'No vulnerabilities established by GenAI evidence.';
    }

    // 5. Cyber Kill Chain
    renderKillChain(analysis.kill_chain || []);
    document.getElementById('attackMethodologyText').textContent = analysis.attack_methodology || 'No attack methodology established by GenAI evidence.';

    // 6. MITRE ATT&CK
    renderMitreMatrix(analysis.mitre_attack || []);

    // 7. IoC Table
    renderIoCTable();

    // 8. STIX 2.1 Inspector
    renderSTIXViewer();

    // 9. Firewall Studio
    renderFirewallStudio();

    // Smooth scroll down to dashboard if user triggered
    dashboardSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderKillChain(stages) {
    const grid = document.getElementById('killChainGrid');
    grid.innerHTML = '';

    stages.forEach((stage, idx) => {
        const card = document.createElement('div');
        card.className = 'p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 hover:border-cyan-800 transition flex flex-col justify-between';
        
        let evidenceHtml = '';
        (stage.evidence || []).slice(0, 3).forEach(ev => {
            evidenceHtml += `<li class="text-[11px] text-slate-300 leading-snug flex items-start gap-1.5">
                <span class="text-cyan-400 mt-1">•</span> <span>${escapeHtml(ev)}</span>
            </li>`;
        });

        card.innerHTML = `
            <div>
                <div class="flex items-center justify-between text-xs font-mono text-slate-400 mb-2">
                    <span class="flex items-center gap-1.5 text-cyan-400 font-bold">
                        <i class="fa-solid ${stage.icon || 'fa-shield'}"></i>
                        Stage ${idx + 1}
                    </span>
                    <span class="text-[10px] text-slate-500">${stage.evidence.length} Evidence</span>
                </div>
                <h4 class="text-xs font-bold text-white mb-2">${stage.phase}</h4>
                <ul class="space-y-1">
                    ${evidenceHtml}
                </ul>
            </div>
        `;
        grid.appendChild(card);
    });
}

function renderMitreMatrix(techniques) {
    document.getElementById('mitreCount').textContent = techniques.length;
    const grid = document.getElementById('mitreGrid');
    grid.innerHTML = '';

    techniques.forEach(tech => {
        const card = document.createElement('div');
        card.className = 'p-4 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-700/80 transition space-y-2';
        card.innerHTML = `
            <div class="flex items-center justify-between text-xs font-mono">
                <a href="https://attack.mitre.org/techniques/${tech.id.replace('.', '/')}" target="_blank" class="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 hover:underline flex items-center gap-1">
                    <span>${tech.id}</span>
                    <i class="fa-solid fa-arrow-up-right-from-square text-[9px]"></i>
                </a>
                <span class="text-[10px] text-slate-400 uppercase tracking-wider">${tech.tactic}</span>
            </div>
            <h4 class="text-xs font-bold text-white">${tech.name}</h4>
            <p class="text-[11px] text-slate-400 line-clamp-2">${tech.description}</p>
            <p class="text-[11px] text-slate-300"><b class="text-slate-400">Evidence:</b> ${escapeHtml(tech.evidence || 'Not provided')}</p>
            <p class="text-[10px] text-slate-500"><b class="text-slate-400">Source page:</b> ${escapeHtml(tech.source_page || 'Unknown')}</p>
            <div class="pt-2 border-t border-slate-900 text-[10px] text-slate-500">
                <b class="text-slate-400">Mitigation:</b> ${tech.mitigation}
            </div>
        `;
        grid.appendChild(card);
    });
}

function renderIoCTable() {
    const tbody = document.getElementById('iocTableBody');
    tbody.innerHTML = '';

    const iocs = currentReportData.iocs || [];
    const query = (document.getElementById('iocSearchInput').value || '').toLowerCase();

    const filtered = iocs.filter(ioc => {
        const matchesType = currentTypeFilter === 'all' || 
            (currentTypeFilter === 'sha256' ? ['sha256', 'sha1', 'md5'].includes(ioc.type) : ioc.type === currentTypeFilter);
        
        const valToSearch = (showDefanged ? (ioc.defanged_value || ioc.defanged) : (ioc.normalized_value || ioc.value)).toLowerCase();
        const matchesQuery = !query || 
            valToSearch.includes(query) || 
            (ioc.role || '').toLowerCase().includes(query) ||
            ioc.type.toLowerCase().includes(query) ||
            (ioc.validation_status || '').toLowerCase().includes(query);

        return matchesType && matchesQuery;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-6 text-slate-500">No matching threat indicators found.</td></tr>`;
        return;
    }

    filtered.forEach(ioc => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-950/60 transition';
        const displayVal = showDefanged ? (ioc.defanged_value || ioc.defanged || ioc.value) : (ioc.normalized_value || ioc.value);
        const status = (ioc.validation_status || 'UNKNOWN').toUpperCase();
        const statusClass = status === 'VALID' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' :
            status === 'PRIVATE' ? 'bg-amber-950 text-amber-400 border-amber-800' :
            status === 'INVALID' ? 'bg-red-950 text-red-400 border-red-800' :
            'bg-slate-800 text-slate-300 border-slate-700';
        const pages = (ioc.source_pages || [ioc.source_page || ioc.page || 1]).join(', ');

        tr.innerHTML = `
            <td class="py-3 px-4">
                <span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold ${getTypeBadgeClass(ioc.type)}">
                    ${ioc.type}
                </span>
            </td>
            <td class="py-3 px-4 font-mono text-white text-xs select-all">
                ${escapeHtml(displayVal)}
            </td>
            <td class="py-3 px-4">
                <span class="px-2 py-0.5 rounded text-[10px] border ${statusClass}">${status}</span>
            </td>
            <td class="py-3 px-4 text-slate-300 text-xs">
                ${escapeHtml(ioc.role || 'Observed Indicator')}
            </td>
            <td class="py-3 px-4">
                <span class="px-2 py-0.5 rounded text-[10px] ${ioc.confidence === 'High' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-300'}">
                    ${ioc.confidence || 'Medium'}
                </span>
            </td>
            <td class="py-3 px-4 text-slate-400 text-center">
                ${ioc.occurrences || 1}
            </td>
            <td class="py-3 px-4 text-slate-400">
                ${escapeHtml(`p. ${pages}`)}
            </td>
            <td class="py-3 px-4 text-right">
                <button onclick="copyToClipboard('${escapeJs(showDefanged ? ioc.defanged : ioc.value)}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition" title="Copy Indicator">
                    <i class="fa-solid fa-copy text-xs"></i>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function getTypeBadgeClass(type) {
    switch (type) {
        case 'ipv4':
        case 'ipv6':
            return 'bg-cyan-950 text-cyan-400 border border-cyan-800';
        case 'domain':
        case 'url':
            return 'bg-blue-950 text-blue-400 border border-blue-800';
        case 'sha256':
        case 'sha1':
        case 'md5':
            return 'bg-purple-950 text-purple-400 border border-purple-800';
        case 'registry':
            return 'bg-amber-950 text-amber-400 border border-amber-800';
        case 'cve':
            return 'bg-red-950 text-red-400 border border-red-800';
        default:
            return 'bg-slate-800 text-slate-300';
    }
}

function toggleDefanging(defanged) {
    showDefanged = defanged;
    const defBtn = document.getElementById('viewDefangedBtn');
    const refBtn = document.getElementById('viewRefangedBtn');

    if (defanged) {
        defBtn.className = 'px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 font-bold';
        refBtn.className = 'px-2 py-0.5 rounded text-slate-400 hover:text-white';
    } else {
        refBtn.className = 'px-2 py-0.5 rounded bg-cyan-900/60 text-cyan-300 font-bold';
        defBtn.className = 'px-2 py-0.5 rounded text-slate-400 hover:text-white';
    }
    renderIoCTable();
}

function filterByType(type) {
    currentTypeFilter = type;
    document.querySelectorAll('#iocTypeFilter .filter-btn').forEach(btn => {
        btn.classList.remove('active', 'bg-cyan-950', 'text-cyan-400', 'border-cyan-800');
        btn.classList.add('bg-slate-950', 'text-slate-400', 'border-slate-800');
    });

    const activeBtn = Array.from(document.querySelectorAll('#iocTypeFilter .filter-btn'))
        .find(b => b.textContent.toLowerCase().includes(type) || (type === 'all' && b.textContent === 'All'));
    if (activeBtn) {
        activeBtn.classList.add('active', 'bg-cyan-950', 'text-cyan-400', 'border-cyan-800');
        activeBtn.classList.remove('bg-slate-950', 'text-slate-400', 'border-slate-800');
    }

    renderIoCTable();
}

function filterIoCs() {
    renderIoCTable();
}

function renderSTIXViewer() {
    const bundle = currentReportData.stix_bundle;
    const viewer = document.getElementById('stixJsonViewer');
    viewer.textContent = JSON.stringify(bundle, null, 2);
    const validation = currentReportData.stix_validation || { valid: false };
    const downloadButton = document.getElementById('downloadStixBtn');
    const validationStatus = document.getElementById('stixValidationStatus');
    downloadButton.disabled = !validation.valid;
    downloadButton.className = validation.valid
        ? 'px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold flex items-center gap-1.5 shadow transition'
        : 'px-3 py-1.5 rounded-lg bg-slate-700 text-slate-500 text-xs font-mono font-semibold flex items-center gap-1.5 shadow transition cursor-not-allowed';
    validationStatus.textContent = validation.valid
        ? `Validated STIX 2.1 bundle (${validation.object_count} objects)`
        : `STIX validation failed: ${(validation.errors || []).join(' ')}`;
    validationStatus.className = validation.valid ? 'text-[10px] font-mono text-emerald-400' : 'text-[10px] font-mono text-red-400';

    // Compute SDO breakdown metrics
    const counts = {};
    (bundle.objects || []).forEach(obj => {
        counts[obj.type] = (counts[obj.type] || 0) + 1;
    });

    const metricsContainer = document.getElementById('stixMetrics');
    metricsContainer.innerHTML = '';

    const labelMap = {
        'identity': 'Identity',
        'threat-actor': 'Threat Actor',
        'malware': 'Malware',
        'attack-pattern': 'Attack Pattern',
        'indicator': 'Indicators',
        'vulnerability': 'Vulnerabilities',
        'relationship': 'Relationships'
    };

    Object.entries(counts).forEach(([type, count]) => {
        const badge = document.createElement('span');
        badge.className = 'px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-slate-300';
        badge.innerHTML = `<span class="text-purple-400 font-bold">${count}</span> ${labelMap[type] || type}`;
        metricsContainer.appendChild(badge);
    });
}

function renderFirewallStudio() {
    selectFirewallTab(currentFirewallTab);
}

function selectFirewallTab(tabKey) {
    currentFirewallTab = tabKey;
    const rules = currentReportData.firewall_rules || {};
    const viewer = document.getElementById('firewallCodeViewer');
    viewer.textContent = rules[tabKey] || '# No configuration generated for this platform.';

    document.querySelectorAll('.fw-tab').forEach(tab => {
        tab.classList.remove('active', 'bg-cyan-950', 'text-cyan-400', 'border-cyan-800');
        tab.classList.add('bg-slate-950', 'text-slate-400', 'border-slate-800');
    });

    const activeTab = Array.from(document.querySelectorAll('.fw-tab'))
        .find(t => t.getAttribute('onclick').includes(tabKey));
    if (activeTab) {
        activeTab.classList.add('active', 'bg-cyan-950', 'text-cyan-400', 'border-cyan-800');
        activeTab.classList.remove('bg-slate-950', 'text-slate-400', 'border-slate-800');
    }
}

// Download & Export Handlers
function downloadSTIX() {
    if (!currentReportData || !currentReportData.stix_bundle) return;
    const validation = currentReportData.stix_validation;
    if (!validation || !validation.valid) {
        showToast('STIX bundle failed validation and cannot be downloaded', true);
        return;
    }
    const jsonStr = JSON.stringify(currentReportData.stix_bundle, null, 2);
    downloadBlob(jsonStr, 'threat_report_stix2.1.json', 'application/json');
    showToast('STIX 2.1 Bundle downloaded');
}

function copySTIX() {
    if (!currentReportData || !currentReportData.stix_bundle) return;
    copyToClipboard(JSON.stringify(currentReportData.stix_bundle, null, 2));
}

function copyFirewallRule() {
    const text = document.getElementById('firewallCodeViewer').textContent;
    copyToClipboard(text);
}

function downloadFirewallRule() {
    const text = document.getElementById('firewallCodeViewer').textContent;
    const extMap = {
        'suricata': 'suricata_rules.rules',
        'palo_alto': 'palo_alto_commands.txt',
        'fortigate': 'fortigate_policy.txt',
        'cisco_asa': 'cisco_asa_acl.txt',
        'iptables': 'iptables_block.sh',
        'zeek': 'zeek_intel.dat',
        'siem_csv': 'threat_indicators_siem.csv',
        'edr_hashes': 'edr_hash_blocklist.csv'
    };
    const filename = extMap[currentFirewallTab] || 'firewall_rules.txt';
    downloadBlob(text, filename, 'text/plain');
    showToast(`Downloaded ${filename}`);
}

function downloadIoCCSV() {
    if (!currentReportData || !currentReportData.firewall_rules) return;
    const csv = currentReportData.firewall_rules.siem_csv;
    downloadBlob(csv, 'extracted_indicators.csv', 'text/csv');
    showToast('Downloaded extracted indicators CSV');
}

function copyAllIoCs() {
    if (!currentReportData || !currentReportData.iocs) return;
    const lines = currentReportData.iocs.map(i => showDefanged ? (i.defanged_value || i.defanged || i.value) : (i.normalized_value || i.value));
    copyToClipboard(lines.join('\n'));
}

// Helper Utilities
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard');
    }).catch(err => {
        console.error(err);
        showToast('Failed to copy', true);
    });
}

function downloadBlob(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function showToast(message, isError = false) {
    const toast = document.getElementById('toast');
    const toastMsg = document.getElementById('toastMsg');
    toastMsg.textContent = message;

    if (isError) {
        toast.className = 'fixed bottom-6 right-6 px-4 py-2.5 rounded-lg bg-slate-900 border border-red-500 text-red-300 text-xs font-mono shadow-2xl transition-all duration-300 translate-y-0 opacity-100 z-50 flex items-center gap-2';
    } else {
        toast.className = 'fixed bottom-6 right-6 px-4 py-2.5 rounded-lg bg-slate-900 border border-cyan-500 text-cyan-300 text-xs font-mono shadow-2xl transition-all duration-300 translate-y-0 opacity-100 z-50 flex items-center gap-2';
    }

    setTimeout(() => {
        toast.classList.add('translate-y-20', 'opacity-0');
    }, 2800);
}

function scrollToSection(id) {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeJs(str) {
    if (!str) return '';
    return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
