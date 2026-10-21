'use strict';

const TERMINAL_STATES = new Set(['completed', 'partial', 'failed', 'cancelled', 'interrupted']);
const CHECK_PAGE_SIZE = 18;
const CHECK_DISPLAY_LIMIT = 100;
const AUDIT_PAGE_SIZE = 100;
const AUDIT_DISPLAY_LIMIT = 500;
const TEMPLATE_PAGE_SIZE = 25;
const TEMPLATE_OFFSET_LIMIT = 100000;
const SCHEDULE_PAGE_SIZE = 25;
const SCHEDULE_OFFSET_LIMIT = 100000;
const FINDING_PAGE_SIZE = 18;
const FINDING_DISPLAY_LIMIT = 100;
const OCCURRENCE_DISPLAY_LIMIT = 100;
const OCCURRENCE_PREVIEW_LIMIT = 16384;
const PROMPT_CATEGORIES = new Set(['system_prompt_extraction', 'instruction_bypass', 'role_manipulation',
    'dan_jailbreak', 'context_manipulation', 'injection_via_encoding', 'payload_injection']);
const GROUP_FIELDS = ['rule_id', 'probe_id', 'probe_version', 'evidence_context_id', 'category',
    'vulnerability_type', 'severity', 'evidence_status', 'control_status', 'test_name', 'path',
    'endpoint', 'full_url', 'title', 'description', 'remediation'];
const groupText = (value, maximum = 256) => typeof value === 'string' && value.length > 0 &&
    value.length <= maximum && value.trim() === value && !/[\x00-\x1f\x7f]/.test(value);
const findingRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const probeIdentity = finding => JSON.stringify([finding.rule_id, finding.probe_id, finding.probe_version]);
const findingPreview = value => {
    const text = String(value ?? '');
    return text.length <= 4096 ? text : text.slice(0, 4096) + ' [Preview truncated; download JSON for complete text]';
};

function findingGroupKey(report, asset, finding, ids, probeCounts) {
    if (report.schema_version !== '1.0' || report.check_schema_version !== '1.0' ||
        !['id', 'provider', 'model'].every(key => groupText(asset[key]) && !/[\[\]]/.test(asset[key])) ||
        !groupText(finding.id) || /[\[\]]/.test(finding.id) || ids.get(finding.id) !== 1 ||
        finding.vulnerability_type !== 'prompt_injection' || finding.evidence_status !== 'confirmed' ||
        !PROMPT_CATEGORIES.has(finding.category) || finding.rule_id !== `prompt_injection.${finding.category}` ||
        finding.probe_id !== `${finding.rule_id}.sample` || !groupText(finding.probe_version) || /[\[\]]/.test(finding.probe_version) ||
        !groupText(finding.evidence_context_id, 128) || /[\[\]]/.test(finding.evidence_context_id) ||
        !['critical', 'high', 'medium', 'low', 'info'].includes(finding.severity) ||
        ['agent_id', 'provider', 'model'].some(key => key in finding && finding[key] !== asset[key === 'agent_id' ? 'id' : key])) return null;
    for (const key of GROUP_FIELDS) {
        if (key in finding && (typeof finding[key] !== 'string' || finding[key].length > 4096 ||
            /[\x00-\x1f\x7f]/.test(finding[key]))) return null;
    }
    const matches = (Array.isArray(asset.checks) ? asset.checks : []).filter(check => check &&
        ['rule_id', 'probe_id', 'probe_version'].every(key => check[key] === finding[key]));
    if (matches.length !== 1) return null;
    const check = matches[0];
    if (check.outcome !== 'confirmed' || !['completed', 'failed'].includes(check.status) ||
        check.evidence_context_id !== finding.evidence_context_id ||
        !Number.isSafeInteger(check.responses_evaluated) || check.responses_evaluated < 1 ||
        !Number.isSafeInteger(check.requests_attempted) || check.requests_attempted < check.responses_evaluated ||
        probeCounts.get(probeIdentity(finding)) > check.responses_evaluated) return null;
    return {key: JSON.stringify(GROUP_FIELDS.map(key => key in finding ? ['value', finding[key]] : ['missing'])),
        evaluated: check.responses_evaluated};
}

function groupFindingOccurrences(report) {
    // Display identity only. Original records, scoring, and lifecycle keys are untouched.
    const groups = [];
    for (const asset of Array.isArray(report.agents) ? report.agents : []) {
        const findings = Array.isArray(asset.vulnerabilities) ? asset.vulnerabilities : [];
        const ids = new Map();
        const probeCounts = new Map();
        for (const finding of findings) {
            if (!findingRecord(finding)) continue;
            ids.set(finding.id, (ids.get(finding.id) || 0) + 1);
            if (['rule_id', 'probe_id', 'probe_version'].every(key => groupText(finding[key]))) {
                const key = probeIdentity(finding);
                probeCounts.set(key, (probeCounts.get(key) || 0) + 1);
            }
        }
        const local = new Map();
        const assetGroups = [];
        for (const original of findings) {
            const finding = findingRecord(original) ? original : {};
            const identity = findingGroupKey(report, asset, finding, ids, probeCounts);
            if (identity && local.has(identity.key)) local.get(identity.key).occurrences.push(original);
            else {
                const group = {asset, finding, occurrences: [original], sampled: Boolean(identity), evaluated: identity?.evaluated};
                assetGroups.push(group);
                if (identity) local.set(identity.key, group);
            }
        }
        for (const group of assetGroups) {
            if (group.sampled && group.occurrences.length > group.evaluated) {
                groups.push(...group.occurrences.map(finding => ({asset, finding, occurrences: [finding], sampled: false})));
            } else groups.push(group);
        }
    }
    return groups;
}

class AIAgentScanner {
    constructor(doc = document, fetcher = (...args) => fetch(...args)) {
        this.doc = doc;
        this.fetcher = fetcher;
        this.token = null;
        this.epoch = 0;
        this.selection = 0;
        this.scanId = null;
        this.terminalAnnouncement = '';
        this.noticeOwner = null;
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
        this.schedule = null;
        this.scheduleBusy = false;
        this.scheduleSelection = 0;
        this.scheduleRequest = 0;
        this.scheduleOffset = 0;
        this.occurrenceRequest = 0;
        this.occurrenceOffset = 0;
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
        this.on('templateEditor', 'input', () => { this.el('reviewScheduleTemplate').checked = false; this.scheduleButtons(); });
        this.on('reviewScheduleTemplate', 'change', () => this.scheduleButtons());
        this.on('createScheduleBtn', 'click', () => this.createSchedule());
        this.on('refreshSchedulesBtn', 'click', () => this.loadSchedules());
        this.on('scheduleList', 'change', () => this.scheduleButtons());
        this.on('openScheduleBtn', 'click', () => this.openSchedule(this.el('scheduleList').value));
        this.on('previousSchedulesBtn', 'click', () => { this.scheduleOffset = Math.max(0, this.scheduleOffset - SCHEDULE_PAGE_SIZE); this.loadSchedules(); });
        this.on('nextSchedulesBtn', 'click', () => { this.scheduleOffset = Math.min(SCHEDULE_OFFSET_LIMIT, this.scheduleOffset + SCHEDULE_PAGE_SIZE); this.loadSchedules(); });
        this.on('enableScheduleBtn', 'click', () => this.changeSchedule('enable'));
        this.on('pauseScheduleBtn', 'click', () => this.changeSchedule('pause'));
        this.on('deleteScheduleBtn', 'click', () => this.deleteSchedule());
        this.on('refreshScheduleBtn', 'click', () => this.schedule && this.openSchedule(this.schedule.id));
        this.on('refreshOccurrencesBtn', 'click', () => this.loadOccurrences());
        this.on('scheduleOccurrences', 'change', () => this.scheduleButtons());
        this.on('openOccurrenceBtn', 'click', () => this.openOccurrence());
        this.on('previousOccurrencesBtn', 'click', () => { this.occurrenceOffset = Math.max(0, this.occurrenceOffset - SCHEDULE_PAGE_SIZE); this.loadOccurrences(); });
        this.on('nextOccurrencesBtn', 'click', () => { this.occurrenceOffset = Math.min(75, this.occurrenceOffset + SCHEDULE_PAGE_SIZE); this.loadOccurrences(); });
        this.on('discardTemplateBtn', 'click', () => {
            if (this.template && !this.templateBusy) {
                this.el('templateEditor').value = this.templateText;
                this.el('reviewScheduleTemplate').checked = false;
                this.scheduleButtons();
                this.notice('Editor reset to the displayed saved revision. No recipe or scan changed.');
            }
        });
    }

    el(id) { return this.doc.getElementById(id); }
    on(id, event, handler) { this.el(id).addEventListener(event, handler); }
    notice(message, error = false, owner = null) {
        this.el('notice').textContent = message;
        this.el('notice').className = error ? 'notice error' : 'notice';
        this.noticeOwner = owner;
    }
    handleError(error, owner = null) {
        if (error.name !== 'AbortError' && error.message !== 'Session changed') this.notice(error.message, true, owner);
    }
    clearReportNotice() {
        if (this.noticeOwner === 'scan-report') this.notice('');
    }
    clearReport() {
        this.clearReportNotice();
        this.reportState = null;
        this.el('reportView').hidden = true;
        for (const id of ['assetList', 'findingList', 'observationList']) this.el(id).replaceChildren();
        this.el('jsonBtn').disabled = this.el('sarifBtn').disabled = true;
        this.el('checkSummary').textContent = '';
        this.el('assetCount').textContent = this.el('findingCount').textContent = '0';
        this.el('findingGroupingSummary').textContent = '';
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
        this.terminalAnnouncement = '';
        this.el('scanAnnouncement').textContent = '';
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
        this.clearSchedules();
        this.historyOffset = 0;
        this.historyRequest += 1;
        this.el('scanHistory').replaceChildren();
        this.el('historyCount').textContent = '';
        for (const id of ['scanHistory', 'openHistoryBtn', 'refreshHistoryBtn', 'previousHistoryBtn', 'nextHistoryBtn']) this.el(id).disabled = true;
        this.notice('Signed out.');
        this.el('operatorKey').focus?.();
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
            this.el('scheduleControls').disabled = false;
            this.templateButtons();
            this.scheduleButtons();
            await Promise.all([this.loadHistory(), this.loadTemplates(), this.loadSchedules()]);
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
            if (!config.source_scan_id) throw new Error('Enter a terminal completed or partial source scan ID.');
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
        this.resetScheduleReview();
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
        this.scheduleButtons();
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
        this.resetScheduleReview();
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
        const epoch = this.epoch;
        const selection = this.templateSelection + 1;
        let deleted = false;
        await this.templateAction(async current => {
            await this.request(`/api/templates/${encodeURIComponent(this.template.id)}`, {method: 'DELETE'});
            if (!current()) return;
            this.template = null;
            this.templateText = '';
            this.el('templateEditor').value = '';
            this.el('templateIdentity').textContent = '';
            this.el('templateEditorView').hidden = true;
            this.resetScheduleReview();
            this.notice('Template deleted. Existing scans are unchanged.');
            deleted = true;
            await this.loadTemplates();
        });
        if (deleted && epoch === this.epoch && selection === this.templateSelection) this.el('refreshTemplatesBtn').focus?.();
    }
    resetScheduleReview() {
        this.el('reviewScheduleTemplate').checked = false;
        this.el('scheduleTemplatePin').textContent = this.template ?
            `Reviewed pin candidate: ${this.template.id} / revision ${this.template.revision}. Read the complete saved definition above.` :
            'Load a saved template above to review its ID and revision.';
        this.scheduleButtons();
    }
    reviewedSchedulePin() {
        return Boolean(this.template && !this.templateBusy && this.el('reviewScheduleTemplate').checked &&
            this.el('templateEditor').value === this.templateText);
    }
    clearOccurrences() {
        this.occurrenceRequest += 1;
        this.occurrenceOffset = 0;
        this.occurrenceHasNext = false;
        this.occurrenceBusy = false;
        this.el('scheduleOccurrences').replaceChildren();
        this.el('occurrenceCount').textContent = '';
    }
    clearSchedules() {
        this.scheduleRequest += 1;
        this.scheduleSelection += 1;
        this.scheduleOffset = 0;
        this.scheduleHasNext = false;
        this.scheduleBusy = false;
        this.schedule = null;
        this.el('scheduleList').replaceChildren();
        this.el('scheduleCount').textContent = '';
        this.el('scheduleDetail').hidden = true;
        for (const id of ['scheduleIdentity', 'scheduleStatus', 'scheduleTiming']) this.el(id).textContent = '';
        this.el('scheduleControls').disabled = true;
        this.el('scheduleInterval').value = '3600';
        this.el('scheduleRuns').value = '4';
        this.clearOccurrences();
        this.resetScheduleReview();
    }
    scheduleButtons() {
        const ready = Boolean(this.token) && !this.scheduleBusy;
        this.el('reviewScheduleTemplate').disabled = !ready || !this.template || this.templateBusy;
        for (const id of ['scheduleInterval', 'scheduleRuns', 'refreshSchedulesBtn', 'scheduleList']) this.el(id).disabled = !ready;
        this.el('createScheduleBtn').disabled = !ready || !this.reviewedSchedulePin();
        this.el('openScheduleBtn').disabled = !ready || !this.el('scheduleList').value;
        this.el('previousSchedulesBtn').disabled = !ready || this.scheduleOffset === 0;
        this.el('nextSchedulesBtn').disabled = !ready || !this.scheduleHasNext || this.scheduleOffset >= SCHEDULE_OFFSET_LIMIT;
        const row = this.schedule;
        const remaining = row && row.state !== 'completed' && row.admitted_runs < row.total_runs;
        const matchingPin = row && this.template && row.template_id === this.template.id && row.template_revision === this.template.revision;
        this.el('enableScheduleBtn').disabled = !ready || !remaining || row.state === 'enabled' || !matchingPin || !this.reviewedSchedulePin();
        this.el('pauseScheduleBtn').disabled = !ready || !row || row.state !== 'enabled';
        this.el('deleteScheduleBtn').disabled = !ready || !row || row.state === 'enabled' || row.outstanding_scan_id !== null;
        this.el('refreshScheduleBtn').disabled = !ready || !row;
        const occurrencesReady = ready && Boolean(row) && !this.occurrenceBusy;
        this.el('refreshOccurrencesBtn').disabled = !occurrencesReady;
        this.el('scheduleOccurrences').disabled = !occurrencesReady || !this.el('scheduleOccurrences').value;
        this.el('openOccurrenceBtn').disabled = !occurrencesReady || !this.el('scheduleOccurrences').value;
        this.el('previousOccurrencesBtn').disabled = !occurrencesReady || this.occurrenceOffset === 0;
        this.el('nextOccurrencesBtn').disabled = !occurrencesReady || !this.occurrenceHasNext || this.occurrenceOffset >= 75;
    }
    validateSchedule(row) {
        const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
        const identity = value => typeof value === 'string' && value.length > 0 && value.length <= 64;
        const utc = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)$/.test(value) && Number.isFinite(Date.parse(value));
        if (!row || !identity(row.id) || !identity(row.template_id) || !integer(row.revision, 1, 2147483647) ||
            !integer(row.template_revision, 1, 2147483647) || !integer(row.interval_seconds, 60, 2592000) ||
            !integer(row.total_runs, 1, 100) || !integer(row.admitted_runs, 0, row.total_runs) ||
            !['disabled', 'enabled', 'paused', 'completed'].includes(row.state) ||
            !(row.pause_reason === null || (typeof row.pause_reason === 'string' && row.pause_reason.length <= 32)) ||
            !(row.outstanding_scan_id === null || identity(row.outstanding_scan_id)) ||
            !(row.next_due_at === null || utc(row.next_due_at))) throw new Error('Server returned an invalid schedule.');
        return row;
    }
    async loadSchedules() {
        if (!this.token) return;
        const epoch = this.epoch;
        const offset = this.scheduleOffset;
        const request = ++this.scheduleRequest;
        try {
            const data = await this.request(`/api/schedules?limit=${SCHEDULE_PAGE_SIZE}&offset=${offset}`);
            if (epoch !== this.epoch || request !== this.scheduleRequest || offset !== this.scheduleOffset) return;
            if (!Array.isArray(data.schedules) || data.schedules.length > SCHEDULE_PAGE_SIZE ||
                !Number.isSafeInteger(data.total) || data.total < 0) throw new Error('Server returned invalid schedule history.');
            for (const row of data.schedules) this.validateSchedule(row);
            const list = this.el('scheduleList');
            list.replaceChildren();
            for (const row of data.schedules) this.append(list, 'option', `${row.id} / ${row.state} / ${row.admitted_runs} of ${row.total_runs} admitted`).value = row.id;
            if (!data.schedules.length) this.append(list, 'option', 'No saved schedules on this page.').value = '';
            this.scheduleHasNext = data.schedules.length > 0 && offset + data.schedules.length < data.total;
            this.el('scheduleCount').textContent = `${data.schedules.length} shown / ${data.total} saved`;
            this.scheduleButtons();
        } catch (error) { if (epoch === this.epoch && request === this.scheduleRequest) this.handleError(error); }
    }
    showSchedule(row) {
        this.validateSchedule(row);
        this.schedule = {...row};
        this.el('scheduleIdentity').textContent = `${row.id} / schedule revision ${row.revision}. Pinned template: ${row.template_id} / revision ${row.template_revision}`;
        this.el('scheduleStatus').textContent = `State: ${row.state}. Reason: ${row.pause_reason || 'none'}. ${row.admitted_runs} of ${row.total_runs} admitted; ${row.total_runs - row.admitted_runs} remaining. Outstanding scan: ${row.outstanding_scan_id || 'none'}.`;
        this.el('scheduleTiming').textContent = `Interval: ${row.interval_seconds} seconds. Next due (UTC): ${row.next_due_at || 'not scheduled'}. Refresh to observe dispatcher changes.`;
        this.el('scheduleDetail').hidden = false;
        this.scheduleButtons();
    }
    async scheduleAction(action) {
        if (!this.token || this.scheduleBusy) return;
        const epoch = this.epoch;
        const selection = ++this.scheduleSelection;
        this.scheduleBusy = true;
        // Invalidate any pending occurrence page before a schedule changes.
        this.occurrenceRequest += 1;
        this.occurrenceBusy = false;
        this.scheduleButtons();
        const current = () => epoch === this.epoch && selection === this.scheduleSelection;
        try { await action(current); }
        catch (error) {
            if (current()) {
                if (error.status === 409) this.notice('Schedule, pinned template, or source changed, or this action is not currently allowed. Refresh detail and review the pin; no automatic retry.', true);
                else if (error.status === 404) this.notice('Schedule or pinned template is missing or unavailable to this organization. Refresh the list.', true);
                else this.handleError(error);
            }
        } finally { if (current()) { this.scheduleBusy = false; this.scheduleButtons(); } }
    }
    async createSchedule() {
        if (!this.reviewedSchedulePin()) { this.notice('Load and review the complete saved template revision first. Unsaved edits cannot be scheduled.', true); return; }
        const pin = {...this.template};
        await this.scheduleAction(async current => {
            const interval = Number(this.el('scheduleInterval').value);
            const runs = Number(this.el('scheduleRuns').value);
            if (!Number.isSafeInteger(interval) || interval < 60 || interval > 2592000 || !Number.isSafeInteger(runs) || runs < 1 || runs > 100) {
                throw new Error('Use an integer interval from 60 to 2592000 seconds and total runs from 1 to 100.');
            }
            const data = await this.request('/api/schedules', {method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({template_id: pin.id, template_revision: pin.revision, interval_seconds: interval, total_runs: runs})});
            if (!current()) return;
            this.validateSchedule(data.schedule);
            if (data.schedule.state !== 'disabled' || data.schedule.template_id !== pin.id || data.schedule.template_revision !== pin.revision ||
                data.schedule.interval_seconds !== interval || data.schedule.total_runs !== runs || data.schedule.revision !== 1 ||
                data.schedule.admitted_runs !== 0 || data.schedule.outstanding_scan_id !== null || data.schedule.next_due_at !== null ||
                data.schedule.pause_reason !== null) throw new Error('Server returned an unexpected schedule pin, recurrence, or state. Refresh the list.');
            this.clearOccurrences();
            this.showSchedule(data.schedule);
            this.append(this.el('scheduleOccurrences'), 'option', 'No admitted occurrences.').value = '';
            this.el('occurrenceCount').textContent = '0 admitted';
            this.el('scheduleIdentity').focus?.();
            this.el('reviewScheduleTemplate').checked = false;
            this.notice('Disabled schedule created. Review the pinned saved recipe again before explicitly enabling. No scan has started.');
            this.scheduleOffset = 0;
            await this.loadSchedules();
        });
    }
    async openSchedule(id) {
        if (!id) return;
        await this.scheduleAction(async current => {
            const data = await this.request(`/api/schedules/${encodeURIComponent(id)}`);
            if (!current()) return;
            this.validateSchedule(data.schedule);
            if (data.schedule.id !== id) throw new Error('Server returned a different schedule.');
            this.clearOccurrences();
            this.showSchedule(data.schedule);
            this.el('reviewScheduleTemplate').checked = false;
            this.el('scheduleIdentity').focus?.();
            this.notice('Schedule loaded. Review its pinned saved template before enabling; no action was taken.');
            await this.loadOccurrences();
        });
    }
    async changeSchedule(action) {
        if (!this.schedule || !['enable', 'pause'].includes(action)) return;
        const row = {...this.schedule};
        if (action === 'enable' && (!this.reviewedSchedulePin() || row.template_id !== this.template.id || row.template_revision !== this.template.revision)) {
            this.notice('Load and explicitly review the exact pinned saved template revision before enabling. Changed pins need a replacement schedule.', true); return;
        }
        await this.scheduleAction(async current => {
            const data = await this.request(`/api/schedules/${encodeURIComponent(row.id)}/${action}`, {method: 'POST',
                headers: {'Content-Type': 'application/json'}, body: JSON.stringify({revision: row.revision})});
            if (!current()) return;
            this.validateSchedule(data.schedule);
            if (data.schedule.id !== row.id || data.schedule.template_id !== row.template_id || data.schedule.template_revision !== row.template_revision) throw new Error('Server returned a different schedule or pin. Refresh detail.');
            if (data.schedule.revision !== row.revision + 1 || data.schedule.interval_seconds !== row.interval_seconds ||
                data.schedule.total_runs !== row.total_runs || (action === 'enable' ? data.schedule.state !== 'enabled' :
                    !['paused', 'completed'].includes(data.schedule.state))) throw new Error('Server did not return the requested schedule transition. Refresh detail.');
            this.showSchedule(data.schedule);
            this.el('reviewScheduleTemplate').checked = false;
            this.el('scheduleIdentity').focus?.();
            this.notice(action === 'enable' ? 'Schedule enabled. Its first due time is one interval from now; refresh to inspect admissions.' : 'Schedule paused. Existing admitted scans are unchanged.');
            await this.loadSchedules();
        });
    }
    async deleteSchedule() {
        if (!this.schedule || this.schedule.state === 'enabled' || this.schedule.outstanding_scan_id !== null) {
            this.notice('Pause the schedule and wait for its outstanding scan before deleting.', true); return;
        }
        const id = this.schedule.id;
        const epoch = this.epoch;
        const selection = this.scheduleSelection + 1;
        let deleted = false;
        await this.scheduleAction(async current => {
            await this.request(`/api/schedules/${encodeURIComponent(id)}`, {method: 'DELETE'});
            if (!current()) return;
            this.schedule = null;
            this.el('scheduleDetail').hidden = true;
            for (const name of ['scheduleIdentity', 'scheduleStatus', 'scheduleTiming']) this.el(name).textContent = '';
            this.clearOccurrences();
            this.notice('Schedule and occurrence mappings deleted. Admitted scans and reports are unchanged.');
            deleted = true;
            await this.loadSchedules();
        });
        if (deleted && epoch === this.epoch && selection === this.scheduleSelection) this.el('refreshSchedulesBtn').focus?.();
    }
    async loadOccurrences() {
        if (!this.token || !this.schedule) return;
        const epoch = this.epoch;
        const selection = this.scheduleSelection;
        const id = this.schedule.id;
        const offset = this.occurrenceOffset;
        const request = ++this.occurrenceRequest;
        const current = () => epoch === this.epoch && selection === this.scheduleSelection && request === this.occurrenceRequest &&
            id === this.schedule?.id && offset === this.occurrenceOffset;
        this.occurrenceBusy = true;
        this.scheduleButtons();
        try {
            const data = await this.request(`/api/schedules/${encodeURIComponent(id)}/occurrences?limit=${SCHEDULE_PAGE_SIZE}&offset=${offset}`);
            if (!current()) return;
            if (!Array.isArray(data.occurrences) || data.occurrences.length > SCHEDULE_PAGE_SIZE || !Number.isSafeInteger(data.total) ||
                data.total < 0 || data.total > 100) throw new Error('Server returned invalid schedule occurrences.');
            let ordinal = offset;
            for (const row of data.occurrences) {
                if (!row || !Number.isSafeInteger(row.ordinal) || row.ordinal <= ordinal || row.ordinal > 100 ||
                    typeof row.scan_id !== 'string' || !row.scan_id || row.scan_id.length > 64 ||
                    typeof row.created_at !== 'string' || !Number.isFinite(Date.parse(row.created_at)) ||
                    !/(?:Z|\+00:00)$/.test(row.created_at)) throw new Error('Server returned an invalid occurrence.');
                ordinal = row.ordinal;
            }
            const list = this.el('scheduleOccurrences');
            list.replaceChildren();
            for (const row of data.occurrences) this.append(list, 'option', `#${row.ordinal} / ${row.created_at} UTC / ${row.scan_id}`).value = row.scan_id;
            if (!data.occurrences.length) this.append(list, 'option', 'No admitted occurrences on this page.').value = '';
            this.occurrenceHasNext = data.occurrences.length > 0 && offset + data.occurrences.length < data.total;
            this.el('occurrenceCount').textContent = `${data.occurrences.length} shown / ${data.total} admitted`;
        } catch (error) {
            if (current()) { this.el('occurrenceCount').textContent = 'Occurrences unavailable. Refresh to retry; admitted scans are unchanged.'; this.handleError(error); }
        } finally { if (current()) { this.occurrenceBusy = false; this.scheduleButtons(); } }
    }
    async openOccurrence() {
        if (!this.token || this.scheduleBusy || this.occurrenceBusy || !this.schedule) return;
        await this.selectScan(this.el('scheduleOccurrences').value);
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
        this.terminalAnnouncement = '';
        this.el('scanAnnouncement').textContent = '';
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
        let reportRequest = false;
        try {
            const data = await this.request(this.path('status'));
            if (epoch !== this.epoch || selection !== this.selection) return;
            this.el('scanStatus').textContent = data.status;
            this.el('scanProgress').value = Math.max(0, Math.min(100, Number(data.progress) || 0));
            this.el('scanPhase').textContent = data.current_phase || data.status;
            const terminal = TERMINAL_STATES.has(data.status);
            this.el('cancelScanBtn').disabled = terminal;
            if (terminal) {
                reportRequest = true;
                try {
                    const reportState = await this.loadResults(selection);
                    if (epoch === this.epoch && selection === this.selection) this.announceTerminal(data.status, reportState);
                } catch (error) {
                    if (epoch === this.epoch && selection === this.selection) this.announceTerminal(data.status, 'unavailable');
                    throw error;
                }
            } else this.timer = setTimeout(() => this.poll(), 1500);
        } catch (error) {
            if (epoch === this.epoch && selection === this.selection) {
                this.el('scanStatus').textContent = 'Unavailable';
                this.el('cancelScanBtn').disabled = true;
                this.handleError(error, reportRequest ? 'scan-report' : null);
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
        if (this.reportState) return this.reportState;
        const epoch = this.epoch;
        let data;
        try { data = await this.request(this.path('results')); }
        catch (error) {
            if (epoch === this.epoch && selection === this.selection && this.reportState) return this.reportState;
            throw error;
        }
        if (epoch !== this.epoch || selection !== this.selection) return;
        if (this.reportState) return this.reportState;
        const report = data.results.pipeline;
        if (!report) {
            this.notice('This scan has no versioned report. Historical numeric scores may not represent completed testing.', false, 'scan-report');
            this.reportState = 'historical';
            return this.reportState;
        }
        this.renderReport(report);
        this.clearReportNotice();
        this.el('jsonBtn').disabled = this.el('sarifBtn').disabled = false;
        this.reportState = 'available';
        return this.reportState;
    }
    announceTerminal(status, reportState) {
        if (!TERMINAL_STATES.has(status)) return;
        const states = {completed: 'Scan completed.', partial: 'Scan finished with partial results.',
            failed: 'Scan failed.', cancelled: 'Scan cancelled.', interrupted: 'Scan interrupted.'};
        const reports = {available: 'Report available. Review incomplete checks and evidence.',
            historical: 'No versioned report is available. Testing completeness is unverified.',
            unavailable: 'Report unavailable. Testing completeness is unverified.'};
        const message = `${states[status]} ${reports[reportState] || reports.unavailable}`;
        if (this.terminalAnnouncement === message) return;
        this.el('scanAnnouncement').textContent = message;
        this.terminalAnnouncement = message;
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
    renderFindingGroups(groups) {
        const container = this.el('findingList');
        container.replaceChildren();
        if (!groups.length) {
            this.append(container, 'p', 'No findings recorded. Check assessment completeness before interpreting this result.');
            return;
        }
        const list = this.append(container, 'div', '');
        list.className = 'finding-groups';
        list.tabIndex = 0;
        list.setAttribute('role', 'region');
        list.setAttribute('aria-label', 'Finding groups');
        const more = this.append(container, 'button', 'Show more finding groups');
        more.type = 'button';
        more.className = 'secondary';
        const progress = this.append(container, 'p', '');
        progress.className = 'hint';
        let rendered = 0;
        const show = () => {
            if (rendered >= Math.min(groups.length, FINDING_DISPLAY_LIMIT)) return;
            for (const group of groups.slice(rendered, Math.min(rendered + FINDING_PAGE_SIZE, FINDING_DISPLAY_LIMIT))) {
                const card = this.append(list, 'article', '');
                card.className = 'item';
                const finding = group.finding;
                this.append(card, 'strong', findingPreview(finding.title || finding.vulnerability_type || 'Finding'));
                this.append(card, 'p', findingPreview([group.asset.name, finding.severity, finding.evidence_status].filter(Boolean).join(' / ')));
                if (finding.category) this.append(card, 'p', findingPreview(`Category: ${finding.category}`));
                if (finding.description) this.append(card, 'p', findingPreview(finding.description));
                this.append(card, 'p', `${group.occurrences.length} ${group.sampled ? 'sample' : 'recorded'} occurrences`);
                this.renderOccurrences(card, group);
                rendered += 1;
            }
            const ownedFocus = this.doc.activeElement === more;
            more.hidden = rendered >= Math.min(groups.length, FINDING_DISPLAY_LIMIT);
            progress.textContent = `${rendered} of ${groups.length} finding groups shown. Counts above cover the full report.`;
            if (more.hidden && ownedFocus) list.focus();
            if (rendered === FINDING_DISPLAY_LIMIT && groups.length > rendered) {
                this.append(container, 'p', `Showing ${FINDING_DISPLAY_LIMIT} of ${groups.length} finding groups. Download JSON for every original occurrence.`);
            }
        };
        more.addEventListener('click', show);
        show();
    }
    renderOccurrences(card, group) {
        const details = this.append(card, 'details', '');
        this.append(details, 'summary', `Original occurrence records (${group.occurrences.length})`);
        const list = this.append(details, 'div', '');
        list.className = 'finding-occurrences';
        list.tabIndex = 0;
        list.setAttribute('role', 'region');
        list.setAttribute('aria-label', findingPreview(`Original occurrence records for ${group.finding.category || 'finding'} / ${group.asset.name || group.asset.id || 'asset'}`));
        const more = this.append(details, 'button', 'Show more occurrences');
        more.type = 'button';
        more.className = 'secondary';
        let rendered = 0;
        const show = () => {
            if (rendered >= Math.min(group.occurrences.length, OCCURRENCE_DISPLAY_LIMIT)) return;
            for (const occurrence of group.occurrences.slice(rendered,
                Math.min(rendered + FINDING_PAGE_SIZE, OCCURRENCE_DISPLAY_LIMIT))) {
                this.append(list, 'strong', `Occurrence ${rendered + 1} of ${group.occurrences.length}`);
                const original = JSON.stringify(occurrence, null, 2) ?? String(occurrence);
                this.append(list, 'pre', original.slice(0, OCCURRENCE_PREVIEW_LIMIT));
                if (original.length > OCCURRENCE_PREVIEW_LIMIT) {
                    this.append(list, 'p', 'Record preview truncated. Download JSON for the complete original record.');
                }
                rendered += 1;
            }
            const ownedFocus = this.doc.activeElement === more;
            more.hidden = rendered >= Math.min(group.occurrences.length, OCCURRENCE_DISPLAY_LIMIT);
            if (more.hidden && ownedFocus) list.focus();
            if (rendered === OCCURRENCE_DISPLAY_LIMIT && group.occurrences.length > rendered) {
                this.append(details, 'p', `Showing ${OCCURRENCE_DISPLAY_LIMIT} of ${group.occurrences.length} occurrences. Download JSON for the complete record.`);
            }
        };
        more.addEventListener('click', show);
        details.addEventListener('toggle', () => { if (details.open && rendered === 0) show(); });
    }
    renderReport(report) {
        this.el('reportView').hidden = false;
        const agents = report.agents || [];
        const findings = agents.flatMap(agent => (agent.vulnerabilities || []).map(finding => ({...finding, agent_name: agent.name})));
        const findingGroups = groupFindingOccurrences(report);
        const observations = (report.security_results || []).flatMap(result =>
            (result.observations || []).map(finding => ({...finding, agent_name: result.agent_name})));
        this.el('assetCount').textContent = String(agents.length);
        this.el('findingCount').textContent = String(findings.length);
        const occurrenceLabel = findingGroups.length && findingGroups.every(group => group.sampled) ? 'sample' : 'recorded';
        this.el('findingGroupingSummary').textContent = `${findingGroups.length} finding groups / ${findings.length} ${occurrenceLabel} occurrences. ` +
            'Grouping is for display only, not a shared-root-cause claim. JSON and SARIF retain every occurrence.';
        const score = report.summary && report.summary.overall_risk_score;
        const modern = report.check_schema_version === '1.0';
        const riskEligible = agent => agent.risk_scoring_policy === 'severity-floor-v2' &&
            ['completed', 'partial', 'failed'].includes(agent.security_status) &&
            Array.isArray(agent.checks) && agent.checks.some(check => {
            if (!Number.isSafeInteger(check.responses_evaluated) || check.responses_evaluated < 1 ||
                !Number.isSafeInteger(check.requests_attempted) || check.requests_attempted < check.responses_evaluated) return false;
            if (check.outcome === 'confirmed' && ['completed', 'failed'].includes(check.status)) {
                return (agent.vulnerabilities || []).some(finding => finding.evidence_status === 'confirmed' &&
                    ['rule_id', 'probe_id', 'probe_version'].every(key => typeof check[key] === 'string' && finding[key] === check[key]));
            }
            return agent.security_status === 'completed' && check.status === 'completed' && check.outcome === 'passed' &&
                typeof check.rule_id === 'string' && !check.rule_id.startsWith('prompt_injection') &&
                check.rule_id !== 'tenant_isolation_violation';
        });
        const riskAvailable = modern && ['completed', 'partial'].includes(report.risk_assessment_status) && agents.some(riskEligible);
        const partialRisk = report.status === 'partial' || report.risk_assessment_status === 'partial';
        this.el('riskScore').textContent = riskAvailable && Number.isFinite(score) ?
            `${score.toFixed(1)} / 100${partialRisk ? ' (partial coverage)' : ''}` : 'Not assessed';
        const checks = agents.flatMap(agent => Array.isArray(agent.checks) ? agent.checks : []);
        this.el('checkSummary').textContent = modern ?
            `Checks: ${checks.filter(check => check.status === 'completed').length} completed / ${checks.filter(check => check.status === 'skipped').length} skipped / ${checks.filter(check => check.status === 'failed').length} failed. Completion is separate from evidence outcome.` :
            'Check evidence unavailable for this historical report. Existing numeric scores remain in the export.';
        this.el('reportNote').textContent = report.error ||
            `${report.status}. ${report.summary?.agents_tested || 0} assets completed security testing. Review skipped and incomplete states below.`;
        if (report.source_inventory?.coverage_complete === false) {
            this.el('reportNote').textContent += ' Source inventory coverage is incomplete; only saved validated assets were tested.';
        }
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
            const partialAsset = agent.risk_coverage_status === 'partial' || ['partial', 'failed'].includes(agent.security_status);
            this.append(card, 'p', riskAvailable && riskEligible(agent) && Number.isFinite(agent.risk_score) ?
                `Risk: ${agent.risk_score.toFixed(1)} / 100${partialAsset ? ' (partial coverage)' : ''}` : 'Risk: Not assessed');
            const assessment = (report.security_results || []).find(result => result.agent_id === agent.id);
            if (assessment && (assessment.reason || assessment.error)) this.append(card, 'p', assessment.reason || assessment.error);
            if (assessment?.limitations?.length) {
                const details = this.append(card, 'details', '');
                this.append(details, 'summary', 'Assessment limitations');
                for (const limitation of assessment.limitations) this.append(details, 'p', limitation);
            }
            this.renderChecks(card, modern ? agent.checks : null, `Check records for ${agent.name || agent.id || 'asset'}`);
            assetList.appendChild(card);
        }
        this.renderFindingGroups(findingGroups);
        this.renderItems('observationList', observations, 'No observations recorded.');
    }
    renderChecks(card, checks, label = 'Check records') {
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
        list.setAttribute('role', 'region');
        list.setAttribute('aria-label', label);
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
            const ownedFocus = this.doc.activeElement === more;
            more.hidden = rendered >= Math.min(checks.length, CHECK_DISPLAY_LIMIT);
            if (more.hidden && ownedFocus) list.focus();
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

if (typeof module !== 'undefined') module.exports = {AIAgentScanner, TERMINAL_STATES, groupFindingOccurrences};
if (typeof document !== 'undefined') new AIAgentScanner();
