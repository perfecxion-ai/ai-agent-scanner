'use strict';

const TERMINAL_STATES = new Set(['completed', 'partial', 'failed', 'cancelled', 'interrupted']);
const CHECK_PAGE_SIZE = 18;
const CHECK_DISPLAY_LIMIT = 100;
const AUDIT_PAGE_SIZE = 100;
const AUDIT_DISPLAY_LIMIT = 500;
const TEMPLATE_PAGE_SIZE = 25;
const TEMPLATE_OFFSET_LIMIT = 100000;

class AIAgentScanner {
    constructor(doc = document, fetcher = (...args) => fetch(...args)) {
        this.doc = doc;
        this.fetcher = fetcher;
        this.token = null;
        this.epoch = 0;
        this.selection = 0;
        this.scanId = null;
        this.timer = null;
        this.pending = new Set();
        this.historyOffset = 0;
        this.historyRequest = 0;
        this.auditRequest = 0;
        this.auditCursor = 0;
        this.auditCount = 0;
        this.templateOffset = 0;
        this.templateRequest = 0;
        this.templateSelection = 0;
        this.templateBusy = false;
        this.template = null;
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
        this.on('refreshAuditBtn', 'click', () => this.loadAudit(true));
        this.on('moreAuditBtn', 'click', () => this.loadAudit());
        this.on('saveTemplateBtn', 'click', () => this.saveTemplate());
        this.on('refreshTemplatesBtn', 'click', () => this.loadTemplates());
        this.on('openTemplateBtn', 'click', () => this.openTemplate(this.el('templateList').value));
        this.on('templateList', 'change', () => this.templateButtons());
        this.on('previousTemplatesBtn', 'click', () => { this.templateOffset = Math.max(0, this.templateOffset - TEMPLATE_PAGE_SIZE); this.loadTemplates(); });
        this.on('nextTemplatesBtn', 'click', () => { this.templateOffset = Math.min(TEMPLATE_OFFSET_LIMIT, this.templateOffset + TEMPLATE_PAGE_SIZE); this.loadTemplates(); });
        this.on('updateTemplateBtn', 'click', () => this.updateTemplate());
        this.on('runTemplateBtn', 'click', () => this.runTemplate());
        this.on('deleteTemplateBtn', 'click', () => this.deleteTemplate());
        this.on('discardTemplateBtn', 'click', () => {
            if (this.template && !this.templateBusy) {
                this.el('templateEditor').value = this.templateText;
                this.notice('Editor reset to the displayed saved revision. No recipe or scan changed.');
            }
        });
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
        this.el('checkSummary').textContent = '';
        this.el('assetCount').textContent = this.el('findingCount').textContent = '0';
        this.el('riskScore').textContent = 'Not assessed';
        this.el('reportNote').textContent = '';
    }
    clearAudit() {
        this.auditRequest += 1;
        this.auditCursor = 0;
        this.auditCount = 0;
        this.el('auditView').hidden = true;
        this.el('auditList').replaceChildren();
        this.el('auditNotice').textContent = '';
        this.el('refreshAuditBtn').disabled = this.el('moreAuditBtn').disabled = true;
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
        this.clearAudit();
        this.clearTemplates();
        this.historyOffset = 0;
        this.historyRequest += 1;
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
            if (!response.ok) {
                const error = new Error(data.error || `Request failed (${response.status}).`);
                error.status = response.status;
                throw error;
            }
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
            this.el('templateControls').disabled = false;
            this.templateButtons();
            await Promise.all([this.loadHistory(), this.loadTemplates()]);
        } catch (error) { if (epoch === this.epoch) this.handleError(error); }
        finally { if (epoch === this.epoch) this.el('loginBtn').disabled = false; }
    }
    setMode() {
        const reuse = this.el('scanType').value === 'security_only';
        this.el('sourceFields').hidden = !reuse;
        this.el('targetFields').hidden = reuse;
        this.el('sourceScanId').required = reuse;
    }
    lines(id) { return this.el(id).value.split('\n').map(value => value.trim()).filter(Boolean); }
    formDefinition() {
        const mode = this.el('scanType').value;
        const config = {};
        let scope = {};
        if (mode === 'security_only') {
            config.source_scan_id = this.el('sourceScanId').value.trim();
            if (!config.source_scan_id) throw new Error('Enter a completed source scan ID.');
            if (this.el('modelOverrides').value.trim()) {
                try {
                    const models = JSON.parse(this.el('modelOverrides').value);
                    if (!models || Array.isArray(models) || typeof models !== 'object' ||
                        Object.keys(models).length > 100 || !Object.values(models).every(model => typeof model === 'string' && model.trim())) {
                        throw new Error('Invalid model map');
                    }
                    config.model_overrides = models;
                } catch { throw new Error('Model selections must be a JSON object mapping up to 100 asset IDs to model names.'); }
            }
        } else {
            const targets = this.lines('networkRanges');
            const isNetwork = target => target.includes('/') || target.includes(':') || /^[0-9.]+$/.test(target);
            scope = {network_ranges: targets.filter(isNetwork), domains: targets.filter(target => !isNetwork(target)),
                     repositories: this.lines('repositories'), traffic_sources: this.lines('trafficSources')};
            if (!Object.values(scope).some(values => values.length)) throw new Error('Enter at least one target.');
        }
        return {scan_name: this.el('scanName').value, scan_type: mode, target_scope: scope, scan_config: config};
    }
    async startScan(event) {
        event.preventDefault();
        let definition;
        try { definition = this.formDefinition(); } catch (error) { return this.handleError(error); }
        this.el('startScanBtn').disabled = true;
        const epoch = this.epoch;
        const selection = this.selection;
        try {
            const data = await this.request('/api/scans', {method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(definition)});
            if (epoch !== this.epoch || selection !== this.selection) return;
            this.notice('Scan accepted. Save its ID to reopen it later.');
            await this.selectScan(data.scan_id);
            await this.loadHistory();
        } catch (error) { if (epoch === this.epoch && selection === this.selection) this.handleError(error); }
        finally { if (epoch === this.epoch) this.el('startScanBtn').disabled = false; }
    }
    clearTemplates() {
        this.templateRequest += 1;
        this.templateSelection += 1;
        this.templateOffset = 0;
        this.template = null;
        this.templateText = '';
        this.templateBusy = false;
        this.templateHasNext = false;
        this.el('templateList').replaceChildren();
        this.el('templateEditor').value = '';
        this.el('templateEditorView').hidden = true;
        this.el('templateIdentity').textContent = this.el('templateCount').textContent = '';
        this.el('templateControls').disabled = true;
        this.templateButtons();
    }
    templateButtons() {
        for (const id of ['saveTemplateBtn', 'refreshTemplatesBtn', 'openTemplateBtn', 'previousTemplatesBtn', 'nextTemplatesBtn']) {
            this.el(id).disabled = !this.token || this.templateBusy;
        }
        this.el('openTemplateBtn').disabled ||= !this.el('templateList').value;
        this.el('previousTemplatesBtn').disabled ||= this.templateOffset === 0;
        this.el('nextTemplatesBtn').disabled ||= !this.templateHasNext || this.templateOffset >= TEMPLATE_OFFSET_LIMIT;
        for (const id of ['updateTemplateBtn', 'runTemplateBtn', 'deleteTemplateBtn', 'discardTemplateBtn', 'templateEditor']) {
            this.el(id).disabled = !this.token || this.templateBusy || !this.template;
        }
    }
    async loadTemplates() {
        if (!this.token) return;
        const offset = this.templateOffset;
        const epoch = this.epoch;
        const request = ++this.templateRequest;
        try {
            const data = await this.request(`/api/templates?limit=${TEMPLATE_PAGE_SIZE}&offset=${offset}`);
            if (epoch !== this.epoch || request !== this.templateRequest || offset !== this.templateOffset) return;
            if (!Array.isArray(data.templates) || data.templates.length > TEMPLATE_PAGE_SIZE ||
                !Number.isSafeInteger(data.total) || data.total < 0) throw new Error('Server returned invalid template history.');
            if (!data.templates.every(template => template && typeof template.id === 'string' &&
                Number.isSafeInteger(template.revision) && template.revision > 0)) throw new Error('Server returned an invalid template.');
            const list = this.el('templateList');
            list.replaceChildren();
            for (const template of data.templates) {
                this.append(list, 'option', `${template.scan_name} / revision ${template.revision}`).value = template.id;
            }
            if (!data.templates.length) this.append(list, 'option', 'No saved templates on this page.').value = '';
            this.templateHasNext = offset + data.templates.length < data.total && data.templates.length > 0;
            this.el('templateCount').textContent = `${data.templates.length} shown / ${data.total} saved`;
            this.templateButtons();
        } catch (error) { if (epoch === this.epoch && request === this.templateRequest) this.handleError(error); }
    }
    showTemplate(template) {
        if (!template || typeof template.id !== 'string' || !Number.isSafeInteger(template.revision) || template.revision < 1 ||
            !['discovery_only', 'full', 'security_only'].includes(template.scan_type) || typeof template.scan_name !== 'string' ||
            !template.target_scope || typeof template.target_scope !== 'object' || Array.isArray(template.target_scope) ||
            !template.scan_config || typeof template.scan_config !== 'object' || Array.isArray(template.scan_config)) {
            throw new Error('Server returned an invalid template definition.');
        }
        this.template = {id: template.id, revision: template.revision};
        const definition = {scan_name: template.scan_name, scan_type: template.scan_type,
            target_scope: template.target_scope, scan_config: template.scan_config};
        this.el('templateEditor').value = JSON.stringify(definition, null, 2);
        this.templateText = this.el('templateEditor').value;
        this.el('templateIdentity').textContent = `${template.id} / revision ${template.revision}`;
        this.el('templateEditorView').hidden = false;
    }
    async templateAction(action, scanSelection = null) {
        if (!this.token || this.templateBusy) return;
        const epoch = this.epoch;
        const selection = ++this.templateSelection;
        this.templateBusy = true;
        this.templateButtons();
        const current = () => epoch === this.epoch && selection === this.templateSelection;
        try { await action(current); }
        catch (error) {
            if (current() && (scanSelection === null || scanSelection === this.selection)) {
                if (error.status === 409) this.notice('Template changed. Reload it before updating or running; your editor text is unchanged.', true);
                else if (error.status === 404) this.notice('Template is missing or unavailable to this organization. Refresh the list.', true);
                else this.handleError(error);
            }
        } finally {
            if (current()) { this.templateBusy = false; this.templateButtons(); }
        }
    }
    async openTemplate(id) {
        if (!id) return;
        if (!this.allowTemplateReplacement()) return;
        await this.templateAction(async current => {
            const data = await this.request(`/api/templates/${encodeURIComponent(id)}`);
            if (!current()) return;
            this.showTemplate(data.template);
            this.notice('Template loaded. Edit the complete definition below; no scan has started.');
        });
    }
    async saveTemplate() {
        if (!this.allowTemplateReplacement()) return;
        await this.templateAction(async current => {
            const definition = this.formDefinition();
            const data = await this.request('/api/templates', {method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(definition)});
            if (!current()) return;
            this.showTemplate(data.template);
            this.notice('Form saved as a new template. No scan has started.');
            this.templateOffset = 0;
            await this.loadTemplates();
        });
    }
    allowTemplateReplacement() {
        if (this.template && this.el('templateEditor').value !== this.templateText) {
            this.notice('Unsaved editor changes. Update the template or discard editor changes before loading or saving another recipe.', true);
            return false;
        }
        return true;
    }
    async updateTemplate() {
        if (!this.template) return;
        await this.templateAction(async current => {
            let definition;
            try { definition = JSON.parse(this.el('templateEditor').value); }
            catch { throw new Error('Template definition must be valid JSON.'); }
            if (!definition || Array.isArray(definition) || typeof definition !== 'object' ||
                Object.keys(definition).some(key => !['scan_name', 'scan_type', 'target_scope', 'scan_config'].includes(key)) ||
                Object.keys(definition).length !== 4) throw new Error('Template definition requires exactly the four displayed fields.');
            const data = await this.request(`/api/templates/${encodeURIComponent(this.template.id)}`, {
                method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...definition, revision: this.template.revision})});
            if (!current()) return;
            this.showTemplate(data.template);
            this.notice('Template updated. No scan has started.');
            await this.loadTemplates();
        });
    }
    async runTemplate() {
        if (!this.template) return;
        const selection = this.selection;
        await this.templateAction(async current => {
            const data = await this.request(`/api/templates/${encodeURIComponent(this.template.id)}/run`, {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({revision: this.template.revision})});
            if (!current() || selection !== this.selection) return;
            this.notice('Saved template revision accepted. Unsaved editor changes were not used.');
            await this.selectScan(data.scan_id);
            await this.loadHistory();
        }, selection);
    }
    async deleteTemplate() {
        if (!this.template) return;
        await this.templateAction(async current => {
            await this.request(`/api/templates/${encodeURIComponent(this.template.id)}`, {method: 'DELETE'});
            if (!current()) return;
            this.template = null;
            this.templateText = '';
            this.el('templateEditor').value = '';
            this.el('templateIdentity').textContent = '';
            this.el('templateEditorView').hidden = true;
            this.notice('Template deleted. Existing scans are unchanged.');
            await this.loadTemplates();
        });
    }
    async openScan(event) {
        event.preventDefault();
        await this.selectScan(this.el('openScanId').value.trim());
    }
    async loadHistory() {
        if (!this.token) return;
        const offset = this.historyOffset;
        const epoch = this.epoch;
        const request = ++this.historyRequest;
        try {
            const data = await this.request(`/api/scans?limit=25&offset=${offset}`);
            if (epoch !== this.epoch || request !== this.historyRequest || offset !== this.historyOffset) return;
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
        } catch (error) { if (epoch === this.epoch && request === this.historyRequest) this.handleError(error); }
    }
    async selectScan(id) {
        if (!id) return;
        this.selection += 1;
        clearTimeout(this.timer);
        this.scanId = id;
        this.clearReport();
        this.clearAudit();
        this.el('emptyState').hidden = true;
        this.el('scanState').hidden = false;
        this.el('selectedScanId').textContent = id;
        this.el('scanStatus').textContent = 'Loading';
        this.el('scanProgress').value = 0;
        this.el('scanPhase').textContent = '';
        this.el('cancelScanBtn').disabled = true;
        this.el('openScanId').value = id;
        await Promise.all([this.poll(), this.loadAudit(true)]);
    }
    path(suffix) { return `/api/scans/${encodeURIComponent(this.scanId)}/${suffix}`; }
    async poll() {
        if (!this.token || !this.scanId) return;
        const selection = this.selection;
        const epoch = this.epoch;
        try {
            const data = await this.request(this.path('status'));
            if (epoch !== this.epoch || selection !== this.selection) return;
            this.el('scanStatus').textContent = data.status;
            this.el('scanProgress').value = Math.max(0, Math.min(100, Number(data.progress) || 0));
            this.el('scanPhase').textContent = data.current_phase || data.status;
            const terminal = TERMINAL_STATES.has(data.status);
            this.el('cancelScanBtn').disabled = terminal;
            if (terminal) {
                await this.loadResults(selection);
            } else this.timer = setTimeout(() => this.poll(), 1500);
        } catch (error) {
            if (epoch === this.epoch && selection === this.selection) {
                this.el('scanStatus').textContent = 'Unavailable';
                this.el('cancelScanBtn').disabled = true;
                this.handleError(error);
            }
        }
    }
    async cancel() {
        this.el('cancelScanBtn').disabled = true;
        const selection = this.selection;
        const epoch = this.epoch;
        try {
            const data = await this.request(this.path('cancel'), {method: 'POST'});
            if (epoch !== this.epoch || selection !== this.selection) return;
            this.notice(data.status === 'cancelled' ? 'Scan cancelled.' : 'Cancellation requested. Waiting for the worker.');
            clearTimeout(this.timer);
            await this.poll();
        } catch (error) { if (epoch === this.epoch && selection === this.selection) this.handleError(error); }
    }
    async loadResults(selection) {
        const epoch = this.epoch;
        const data = await this.request(this.path('results'));
        if (epoch !== this.epoch || selection !== this.selection) return;
        const report = data.results.pipeline;
        if (!report) {
            this.notice('This scan has no versioned report. Historical numeric scores may not represent completed testing.');
            return;
        }
        this.renderReport(report);
        this.el('jsonBtn').disabled = this.el('sarifBtn').disabled = false;
    }
    async loadAudit(reset = false) {
        if (!this.token || !this.scanId || (!reset && this.auditCount >= AUDIT_DISPLAY_LIMIT)) return;
        const selection = this.selection;
        const epoch = this.epoch;
        const request = ++this.auditRequest;
        const after = reset ? 0 : this.auditCursor;
        const isCurrent = () => epoch === this.epoch && selection === this.selection && request === this.auditRequest;
        this.el('auditView').hidden = false;
        this.el('refreshAuditBtn').disabled = this.el('moreAuditBtn').disabled = true;
        this.el('auditNotice').textContent = 'Loading audit history...';
        try {
            const data = await this.request(this.path(`audit?limit=${AUDIT_PAGE_SIZE}&after=${after}`));
            if (!isCurrent()) return;
            if (!Array.isArray(data.events) || data.events.length > AUDIT_PAGE_SIZE) throw new Error('Server returned invalid audit history.');
            let cursor = after;
            for (const event of data.events) {
                if (!event || !Number.isSafeInteger(event.id) || event.id <= cursor) throw new Error('Server returned an invalid audit cursor.');
                cursor = event.id;
            }
            if (data.next_after !== cursor) throw new Error('Server returned an invalid audit cursor.');
            if (reset) {
                this.el('auditList').replaceChildren();
                this.auditCount = 0;
            }
            for (const event of data.events.slice(0, AUDIT_DISPLAY_LIMIT - this.auditCount)) {
                const row = this.append(this.el('auditList'), 'li', '');
                this.append(row, 'strong', event.event || 'Event');
                this.append(row, 'p', `${event.previous_status || 'New'} to ${event.status || 'Unknown'}`);
                this.append(row, 'p', event.created_at ? `UTC: ${event.created_at}` : 'Timestamp unavailable');
                this.auditCount += 1;
            }
            this.auditCursor = cursor;
            this.el('moreAuditBtn').disabled = data.events.length < AUDIT_PAGE_SIZE || this.auditCount >= AUDIT_DISPLAY_LIMIT;
            this.el('auditNotice').textContent = this.auditCount >= AUDIT_DISPLAY_LIMIT ?
                `Showing ${AUDIT_DISPLAY_LIMIT} events. Refresh to restart the timeline.` :
                this.auditCount ? `${this.auditCount} audit events shown, oldest first.` : 'No audit events recorded for this scan.';
        } catch (error) {
            if (isCurrent() && error.name !== 'AbortError' && error.message !== 'Session changed') {
                this.el('auditNotice').textContent = `Audit history unavailable: ${error.message}`;
                this.el('moreAuditBtn').disabled = this.auditCount === 0 || this.auditCount >= AUDIT_DISPLAY_LIMIT;
            }
        } finally {
            if (isCurrent()) this.el('refreshAuditBtn').disabled = false;
        }
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
        const modern = report.check_schema_version === '1.0';
        const riskEligible = agent => agent.security_status === 'completed' && Array.isArray(agent.checks) && agent.checks.some(check =>
            check.status === 'completed' && ['passed', 'confirmed'].includes(check.outcome) &&
            Number.isSafeInteger(check.responses_evaluated) && check.responses_evaluated > 0 &&
            Number.isSafeInteger(check.requests_attempted) && check.requests_attempted >= check.responses_evaluated);
        const riskCompleted = modern && report.risk_assessment_status === 'completed' && agents.some(riskEligible);
        this.el('riskScore').textContent = riskCompleted && Number.isFinite(score) ? `${score.toFixed(1)} / 100` : 'Not assessed';
        const checks = agents.flatMap(agent => Array.isArray(agent.checks) ? agent.checks : []);
        this.el('checkSummary').textContent = modern ?
            `Checks: ${checks.filter(check => check.status === 'completed').length} completed / ${checks.filter(check => check.status === 'skipped').length} skipped / ${checks.filter(check => check.status === 'failed').length} failed. Completion is separate from evidence outcome.` :
            'Check evidence unavailable for this historical report. Existing numeric scores remain in the export.';
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
            if (agent.metadata?.resource_id) this.append(card, 'p', `Cloud resource: ${agent.metadata.resource_id}`);
            this.append(card, 'p', riskCompleted && riskEligible(agent) && Number.isFinite(agent.risk_score) ? `Risk: ${agent.risk_score.toFixed(1)} / 100` : 'Risk: Not assessed');
            const assessment = (report.security_results || []).find(result => result.agent_id === agent.id);
            if (assessment && (assessment.reason || assessment.error)) this.append(card, 'p', assessment.reason || assessment.error);
            if (assessment?.limitations?.length) {
                const details = this.append(card, 'details', '');
                this.append(details, 'summary', 'Assessment limitations');
                for (const limitation of assessment.limitations) this.append(details, 'p', limitation);
            }
            this.renderChecks(card, modern ? agent.checks : null);
            assetList.appendChild(card);
        }
        this.renderItems('findingList', findings, 'No findings recorded. Check assessment completeness before interpreting this result.');
        this.renderItems('observationList', observations, 'No observations recorded.');
    }
    renderChecks(card, checks) {
        if (!Array.isArray(checks)) {
            this.append(card, 'p', 'Check evidence unavailable for this report.');
            return;
        }
        if (!checks.length) {
            this.append(card, 'p', 'No check records supplied.');
            return;
        }
        const details = this.append(card, 'details', '');
        this.append(details, 'summary', `Check records (${checks.length})`);
        const list = this.append(details, 'div', '');
        list.className = 'check-list';
        list.tabIndex = 0;
        const more = this.append(details, 'button', 'Show more checks');
        more.type = 'button';
        more.className = 'secondary';
        let rendered = 0;
        const show = () => {
            if (rendered >= Math.min(checks.length, CHECK_DISPLAY_LIMIT)) return;
            for (const check of checks.slice(rendered, Math.min(rendered + CHECK_PAGE_SIZE, CHECK_DISPLAY_LIMIT))) {
                const row = this.append(list, 'div', '');
                row.className = 'check-record';
                this.append(row, 'strong', check.rule_id || 'Unknown rule');
                this.append(row, 'p', `${check.status || 'Unknown execution'} / ${check.outcome || 'Unknown outcome'}`);
                this.append(row, 'p', `Responses evaluated: ${Number.isSafeInteger(check.responses_evaluated) ? check.responses_evaluated : 'Unknown'}`);
                if (check.reason) this.append(row, 'p', check.reason);
                rendered += 1;
            }
            more.hidden = rendered >= Math.min(checks.length, CHECK_DISPLAY_LIMIT);
            if (rendered === CHECK_DISPLAY_LIMIT && checks.length > rendered) {
                this.append(details, 'p', `Showing ${CHECK_DISPLAY_LIMIT} of ${checks.length} checks. Download JSON for the complete record.`);
            }
        };
        more.addEventListener('click', show);
        show();
    }
    async download(format) {
        const selection = this.selection;
        const epoch = this.epoch;
        try {
            const report = await this.request(this.path(`report?format=${format}`));
            if (epoch !== this.epoch || selection !== this.selection) return;
            const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], {type: 'application/json'}));
            const link = this.doc.createElement('a');
            link.href = url;
            link.download = `scan-${this.scanId.replace(/[^a-zA-Z0-9_-]/g, '_')}.${format === 'sarif' ? 'sarif' : 'json'}`;
            link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (error) { if (epoch === this.epoch && selection === this.selection) this.handleError(error); }
    }
}

if (typeof module !== 'undefined') module.exports = {AIAgentScanner, TERMINAL_STATES};
if (typeof document !== 'undefined') new AIAgentScanner();
