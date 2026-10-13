'use strict';

const TERMINAL_STATES = new Set(['completed', 'partial', 'failed', 'cancelled', 'interrupted']);

class AIAgentScanner {
    constructor(doc = document, fetcher = fetch) {
        this.doc = doc;
        this.fetcher = fetcher;
        this.token = null;
        this.epoch = 0;
        this.selection = 0;
        this.scanId = null;
        this.timer = null;
        this.pending = new Set();
        this.historyOffset = 0;
        this.on('loginForm', 'submit', event => this.login(event));
        this.on('logoutBtn', 'click', () => this.logout());
        this.on('scanForm', 'submit', event => this.startScan(event));
        this.on('openScanForm', 'submit', event => this.openScan(event));
        this.on('scanType', 'change', () => this.setMode());
        this.on('cancelScanBtn', 'click', () => this.cancel());
        this.on('jsonBtn', 'click', () => this.download('json'));
        this.on('sarifBtn', 'click', () => this.download('sarif'));
        this.on('refreshHistoryBtn', 'click', () => this.loadHistory());
        this.on('openHistoryBtn', 'click', () => this.selectScan(this.el('scanHistory').value));
        this.on('previousHistoryBtn', 'click', () => { this.historyOffset = Math.max(0, this.historyOffset - 25); this.loadHistory(); });
        this.on('nextHistoryBtn', 'click', () => { this.historyOffset += 25; this.loadHistory(); });
    }

    el(id) { return this.doc.getElementById(id); }
    on(id, event, handler) { this.el(id).addEventListener(event, handler); }
    notice(message, error = false) {
        this.el('notice').textContent = message;
        this.el('notice').className = error ? 'notice error' : 'notice';
    }
    handleError(error) {
        if (error.name !== 'AbortError' && error.message !== 'Session changed') this.notice(error.message, true);
    }
    clearReport() {
        this.el('reportView').hidden = true;
        for (const id of ['assetList', 'findingList', 'observationList']) this.el(id).replaceChildren();
        this.el('jsonBtn').disabled = this.el('sarifBtn').disabled = true;
    }
    logout() {
        this.epoch += 1;
        this.selection += 1;
        this.token = null;
        this.scanId = null;
        clearTimeout(this.timer);
        for (const controller of this.pending) controller.abort();
        this.pending.clear();
        this.el('operatorKey').value = '';
        this.el('scanControls').disabled = true;
        this.el('startScanBtn').disabled = false;
        this.el('openScanBtn').disabled = this.el('logoutBtn').disabled = true;
        this.el('loginBtn').disabled = false;
        this.el('cancelScanBtn').disabled = true;
        this.el('scanState').hidden = true;
        this.el('selectedScanId').textContent = '';
        this.el('openScanId').value = '';
        this.el('emptyState').hidden = false;
        this.clearReport();
        this.historyOffset = 0;
        this.el('scanHistory').replaceChildren();
        this.el('historyCount').textContent = '';
        for (const id of ['scanHistory', 'openHistoryBtn', 'refreshHistoryBtn', 'previousHistoryBtn', 'nextHistoryBtn']) this.el(id).disabled = true;
        this.notice('Signed out.');
    }
    async request(path, options = {}, authenticated = true) {
        if (authenticated && !this.token) throw new Error('Sign in first.');
        const epoch = this.epoch;
        const controller = new AbortController();
        this.pending.add(controller);
        try {
            const response = await this.fetcher(path, {
                ...options, signal: controller.signal, cache: 'no-store',
                headers: {...options.headers, ...(authenticated ? {Authorization: `Bearer ${this.token}`} : {})}
            });
            if (epoch !== this.epoch) throw new Error('Session changed');
            if (response.status === 401 && authenticated) {
                this.logout();
                throw new Error('Session expired. Sign in again.');
            }
            let data;
            try { data = await response.json(); } catch { throw new Error('Server returned an unreadable response.'); }
            if (epoch !== this.epoch) throw new Error('Session changed');
            if (!response.ok) throw new Error(data.error || `Request failed (${response.status}).`);
            return data;
        } finally { this.pending.delete(controller); }
    }
    async login(event) {
        event.preventDefault();
        const key = this.el('operatorKey').value;
        this.logout();
        this.el('loginBtn').disabled = true;
        const epoch = this.epoch;
        try {
            const data = await this.request('/api/auth/token', {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({api_key: key})
            }, false);
            if (typeof data.token !== 'string' || !data.token) throw new Error('Server did not issue a token.');
            this.token = data.token;
            this.el('scanControls').disabled = false;
            this.el('openScanBtn').disabled = this.el('logoutBtn').disabled = false;
            this.notice('Signed in. Your token stays in this page only.');
            this.el('refreshHistoryBtn').disabled = false;
            await this.loadHistory();
        } catch (error) { this.handleError(error); }
        finally { if (epoch === this.epoch) this.el('loginBtn').disabled = false; }
    }
    setMode() {
        const reuse = this.el('scanType').value === 'security_only';
        this.el('sourceFields').hidden = !reuse;
        this.el('targetFields').hidden = reuse;
        this.el('sourceScanId').required = reuse;
    }
    lines(id) { return this.el(id).value.split('\n').map(value => value.trim()).filter(Boolean); }
    async startScan(event) {
        event.preventDefault();
        const mode = this.el('scanType').value;
        const config = {};
        let scope = {};
        if (mode === 'security_only') {
            config.source_scan_id = this.el('sourceScanId').value.trim();
            if (!config.source_scan_id) return this.notice('Enter a completed source scan ID.', true);
            if (this.el('modelOverrides').value.trim()) {
                try {
                    const models = JSON.parse(this.el('modelOverrides').value);
                    if (!models || Array.isArray(models) || typeof models !== 'object' ||
                        Object.keys(models).length > 100 || !Object.values(models).every(model => typeof model === 'string' && model.trim())) {
                        throw new Error('Invalid model map');
                    }
                    config.model_overrides = models;
                } catch { return this.notice('Model selections must be a JSON object mapping up to 100 asset IDs to model names.', true); }
            }
        } else {
            const targets = this.lines('networkRanges');
            const isNetwork = target => target.includes('/') || target.includes(':') || /^[0-9.]+$/.test(target);
            scope = {network_ranges: targets.filter(isNetwork), domains: targets.filter(target => !isNetwork(target)),
                     repositories: this.lines('repositories'), traffic_sources: this.lines('trafficSources')};
            if (!Object.values(scope).some(values => values.length)) return this.notice('Enter at least one target.', true);
        }
        this.el('startScanBtn').disabled = true;
        const epoch = this.epoch;
        try {
            const data = await this.request('/api/scans', {method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({scan_name: this.el('scanName').value, scan_type: mode, target_scope: scope, scan_config: config})});
            this.notice('Scan accepted. Save its ID to reopen it later.');
            await this.selectScan(data.scan_id);
            await this.loadHistory();
        } catch (error) { this.handleError(error); }
        finally { if (epoch === this.epoch) this.el('startScanBtn').disabled = false; }
    }
    async openScan(event) {
        event.preventDefault();
        await this.selectScan(this.el('openScanId').value.trim());
    }
    async loadHistory() {
        if (!this.token) return;
        const offset = this.historyOffset;
        try {
            const data = await this.request(`/api/scans?limit=25&offset=${offset}`);
            if (offset !== this.historyOffset) return;
            const scans = data.scans || [];
            const select = this.el('scanHistory');
            select.replaceChildren();
            for (const scan of scans) {
                const option = this.append(select, 'option', `${scan.scan_name} / ${scan.status} / ${scan.scan_id}`);
                option.value = scan.scan_id;
            }
            if (!scans.length) this.append(select, 'option', 'No saved scans on this page.').value = '';
            select.disabled = this.el('openHistoryBtn').disabled = !scans.length;
            this.el('previousHistoryBtn').disabled = offset === 0;
            this.el('nextHistoryBtn').disabled = offset + scans.length >= (data.total || 0);
            this.el('historyCount').textContent = `${scans.length} shown / ${data.total || 0} saved`;
        } catch (error) { this.handleError(error); }
    }
    async selectScan(id) {
        if (!id) return;
        this.selection += 1;
        clearTimeout(this.timer);
        this.scanId = id;
        this.clearReport();
        this.el('emptyState').hidden = true;
        this.el('scanState').hidden = false;
        this.el('selectedScanId').textContent = id;
        this.el('scanStatus').textContent = 'Loading';
        this.el('scanProgress').value = 0;
        this.el('scanPhase').textContent = '';
        this.el('cancelScanBtn').disabled = true;
        this.el('openScanId').value = id;
        await this.poll();
    }
    path(suffix) { return `/api/scans/${encodeURIComponent(this.scanId)}/${suffix}`; }
    async poll() {
        if (!this.token || !this.scanId) return;
        const selection = this.selection;
        try {
            const data = await this.request(this.path('status'));
            if (selection !== this.selection) return;
            this.el('scanStatus').textContent = data.status;
            this.el('scanProgress').value = Math.max(0, Math.min(100, Number(data.progress) || 0));
            this.el('scanPhase').textContent = data.current_phase || data.status;
            const terminal = TERMINAL_STATES.has(data.status);
            this.el('cancelScanBtn').disabled = terminal;
            if (terminal) {
                await this.loadResults(selection);
            } else this.timer = setTimeout(() => this.poll(), 1500);
        } catch (error) {
            if (selection === this.selection) {
                this.el('scanStatus').textContent = 'Unavailable';
                this.el('cancelScanBtn').disabled = true;
                this.handleError(error);
            }
        }
    }
    async cancel() {
        this.el('cancelScanBtn').disabled = true;
        const selection = this.selection;
        try {
            const data = await this.request(this.path('cancel'), {method: 'POST'});
            if (selection !== this.selection) return;
            this.notice(data.status === 'cancelled' ? 'Scan cancelled.' : 'Cancellation requested. Waiting for the worker.');
            clearTimeout(this.timer);
            await this.poll();
        } catch (error) { this.handleError(error); }
    }
    async loadResults(selection) {
        const data = await this.request(this.path('results'));
        if (selection !== this.selection) return;
        const report = data.results.pipeline;
        if (!report) {
            this.notice('This scan has no versioned report. Historical numeric scores may not represent completed testing.');
            return;
        }
        this.renderReport(report);
        this.el('jsonBtn').disabled = this.el('sarifBtn').disabled = false;
    }
    append(parent, tag, text) {
        const node = this.doc.createElement(tag);
        node.textContent = text;
        parent.appendChild(node);
        return node;
    }
    renderItems(id, items, empty) {
        const container = this.el(id);
        container.replaceChildren();
        if (!items.length) { this.append(container, 'p', empty); return; }
        for (const item of items) {
            const card = this.doc.createElement('article');
            card.className = 'item';
            this.append(card, 'strong', item.title || item.vulnerability_type || 'Observation');
            this.append(card, 'p', [item.agent_name, item.severity, item.evidence_status].filter(Boolean).join(' / '));
            if (item.description) this.append(card, 'p', item.description);
            const details = this.append(card, 'details', '');
            this.append(details, 'summary', 'Evidence and details');
            this.append(details, 'pre', JSON.stringify(item, null, 2));
            container.appendChild(card);
        }
    }
    renderReport(report) {
        this.el('reportView').hidden = false;
        const agents = report.agents || [];
        const findings = agents.flatMap(agent => (agent.vulnerabilities || []).map(finding => ({...finding, agent_name: agent.name})));
        const observations = (report.security_results || []).flatMap(result =>
            (result.observations || []).map(finding => ({...finding, agent_name: result.agent_name})));
        this.el('assetCount').textContent = String(agents.length);
        this.el('findingCount').textContent = String(findings.length);
        const score = report.summary && report.summary.overall_risk_score;
        this.el('riskScore').textContent = typeof score === 'number' ? `${score.toFixed(1)} / 100` : 'Not assessed';
        this.el('reportNote').textContent = report.error ||
            `${report.status}. ${report.summary?.agents_tested || 0} assets completed security testing. Review skipped and incomplete states below.`;
        const assetList = this.el('assetList');
        assetList.replaceChildren();
        if (!agents.length) this.append(assetList, 'p', 'No assets recorded.');
        for (const agent of agents) {
            const card = this.doc.createElement('article');
            card.className = 'item';
            this.append(card, 'strong', agent.name || agent.id);
            this.append(card, 'p', `Asset ID: ${agent.id}`);
            this.append(card, 'p', `${agent.provider || 'Unknown provider'} / ${agent.security_status || 'unknown'}`);
            this.append(card, 'p', agent.endpoint || 'No endpoint');
            this.append(card, 'p', typeof agent.risk_score === 'number' ? `Risk: ${agent.risk_score.toFixed(1)} / 100` : 'Risk: Not assessed');
            const assessment = (report.security_results || []).find(result => result.agent_id === agent.id);
            if (assessment && (assessment.reason || assessment.error)) this.append(card, 'p', assessment.reason || assessment.error);
            if (assessment?.limitations?.length) {
                const details = this.append(card, 'details', '');
                this.append(details, 'summary', 'Assessment limitations');
                for (const limitation of assessment.limitations) this.append(details, 'p', limitation);
            }
            assetList.appendChild(card);
        }
        this.renderItems('findingList', findings, 'No findings recorded. Check assessment completeness before interpreting this result.');
        this.renderItems('observationList', observations, 'No observations recorded.');
    }
    async download(format) {
        const selection = this.selection;
        try {
            const report = await this.request(this.path(`report?format=${format}`));
            if (selection !== this.selection) return;
            const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
            const link = this.doc.createElement('a');
            link.href = url;
            link.download = `scan-${this.scanId.replace(/[^a-zA-Z0-9_-]/g, '_')}.${format === 'sarif' ? 'sarif' : 'json'}`;
            link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (error) { this.handleError(error); }
    }
}

if (typeof module !== 'undefined') module.exports = {AIAgentScanner, TERMINAL_STATES};
if (typeof document !== 'undefined') new AIAgentScanner();
