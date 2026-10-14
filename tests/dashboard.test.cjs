const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {AIAgentScanner, TERMINAL_STATES} = require('../static/js/dashboard.js');

class Element {
    constructor(tag = 'div') { this.tagName = tag; this.children = []; this.value = ''; this.textContent = ''; this.disabled = false; this.hidden = false; this.handlers = {}; }
    addEventListener(event, handler) { this.handlers[event] = handler; }
    appendChild(child) { this.children.push(child); return child; }
    replaceChildren(...children) { this.children = children; }
    click() { this.clicked = true; if (this.handlers.click) this.handlers.click(); }
    set innerHTML(value) { throw new Error('Unsafe HTML rendering'); }
}

function fixture(fetcher) {
    const elements = new Map();
    const doc = {getElementById(id) { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
                 createElement(tag) { return new Element(tag); }};
    const app = new AIAgentScanner(doc, fetcher);
    return {app, doc};
}
const response = (data, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => data});
const event = {preventDefault() {}};
const texts = node => [node.textContent, ...node.children.flatMap(texts)];
const checkedReport = (checks, score = null) => ({status: 'completed', check_schema_version: '1.0',
    risk_assessment_status: score === null ? 'not_assessed' : 'completed',
    agents: [{id: 'asset', name: 'Fixture', security_status: 'completed', risk_score: score, checks, vulnerabilities: []}],
    security_results: [], summary: {overall_risk_score: score}});
const auditEvent = id => ({id, event: 'claim', previous_status: 'queued', status: 'running', created_at: '2026-10-13T10:00:00'});
const savedTemplate = (changes = {}) => ({id: 'recipe', revision: 3, scan_name: 'Lab recipe', scan_type: 'discovery_only',
    target_scope: {network_ranges: ['192.0.2.0/28'], active_probe: false}, scan_config: {timeout_seconds: 120}, ...changes});

test('sign in clears credential input and authenticated calls use bearer token', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => { calls.push({path, options}); return response({token: 'fixture-token'}); });
    app.el('operatorKey').value = 'operator-secret';
    await app.login(event);
    assert.equal(app.el('operatorKey').value, '');
    assert.equal(app.token, 'fixture-token');
    assert.equal(app.el('scanControls').disabled, false);
    await app.request('/api/agents');
    assert.equal(calls[1].options.headers.Authorization, 'Bearer fixture-token');
    app.logout();
    assert.equal(app.token, null);
    assert.equal(app.el('scanControls').disabled, true);
});

test('late login response cannot resurrect a signed out session', async () => {
    let resolve;
    const {app} = fixture(() => new Promise(done => { resolve = done; }));
    app.el('operatorKey').value = 'operator-secret';
    const login = app.login(event);
    app.logout();
    resolve(response({token: 'late-token'}));
    await login;
    assert.equal(app.token, null);
    assert.equal(app.el('scanControls').disabled, true);
});

test('expired bearer session clears protected content', async () => {
    const {app} = fixture(async () => response({error: 'expired'}, 401));
    app.token = 'expired-token';
    app.el('findingList').appendChild(new Element());
    await assert.rejects(app.request('/api/agents'), /Session expired/);
    assert.equal(app.token, null);
    assert.equal(app.el('findingList').children.length, 0);
});

test('terminal states load results without scheduling another poll', async () => {
    for (const status of TERMINAL_STATES) {
        const {app} = fixture(async path => path.endsWith('/status') ? response({status, progress: 100}) :
            response({results: {pipeline: {status, agents: [], security_results: [], summary: {overall_risk_score: null}}}}));
        app.token = 'fixture-token'; app.scanId = 'fixture';
        await app.poll();
        assert.equal(app.timer, null);
        assert.equal(app.el('cancelScanBtn').disabled, true);
        assert.equal(app.el('riskScore').textContent, 'Not assessed');
        assert.equal(app.el('jsonBtn').disabled, false);
    }
});

test('queued 202 response selects scan and sends IPv6 as a network target', async () => {
    let request;
    const {app} = fixture(async (path, options) => { if (!options.body) return response({scans: [], total: 0}); request = JSON.parse(options.body); return response({scan_id: 'queued-id'}, 202); });
    app.token = 'fixture-token'; app.el('scanType').value = 'discovery_only';
    app.el('networkRanges').value = '2001:db8::1\nlab.example.test';
    app.selectScan = async id => { app.scanId = id; };
    await app.startScan(event);
    assert.equal(app.scanId, 'queued-id');
    assert.deepEqual(request.target_scope.network_ranges, ['2001:db8::1']);
    assert.deepEqual(request.target_scope.domains, ['lab.example.test']);
});

test('security-only scan sends source ID without new targets', async () => {
    let request;
    const {app} = fixture(async (path, options) => { if (!options.body) return response({scans: [], total: 0}); request = JSON.parse(options.body); return response({scan_id: 'queued-id'}, 202); });
    app.token = 'fixture-token'; app.el('scanType').value = 'security_only'; app.el('sourceScanId').value = 'source-id';
    app.el('networkRanges').value = 'ignored.example.test'; app.selectScan = async () => {};
    await app.startScan(event);
    assert.deepEqual(request.target_scope, {});
    assert.deepEqual(request.scan_config, {source_scan_id: 'source-id'});
    app.el('modelOverrides').value = '{"asset-id":"fixture-model"}';
    await app.startScan(event);
    assert.deepEqual(request.scan_config.model_overrides, {'asset-id': 'fixture-model'});
});

test('findings and observations render as text and remain separate', () => {
    const {app} = fixture();
    const hostile = '<img src=x onerror=alert(1)>';
    app.renderReport({status: 'partial', agents: [{name: hostile, provider: 'fixture', security_status: 'skipped',
        risk_score: null, vulnerabilities: [{title: hostile, description: hostile}]}],
        security_results: [{agent_name: hostile, observations: [{title: 'Heuristic', evidence_status: 'heuristic'}]}],
        summary: {overall_risk_score: null}});
    assert.equal(app.el('findingList').children[0].children[0].textContent, hostile);
    assert.equal(app.el('observationList').children[0].children[0].textContent, 'Heuristic');
    assert.equal(app.el('assetList').children[0].children[0].textContent, hostile);
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
});

test('cancel uses authenticated POST and rechecks selected scan', async () => {
    let request;
    const {app} = fixture(async (path, options) => { request = {path, options}; return response({status: 'cancel_requested'}, 202); });
    app.token = 'fixture-token'; app.scanId = 'fixture'; let polled = false; app.poll = async () => { polled = true; };
    await app.cancel();
    assert.equal(request.path, '/api/scans/fixture/cancel');
    assert.equal(request.options.method, 'POST');
    assert.equal(request.options.headers.Authorization, 'Bearer fixture-token');
    assert.equal(polled, true);
});

test('static assets have no CDN, unsafe HTML assignment, or browser token storage', () => {
    const html = fs.readFileSync(require.resolve('../templates/dashboard.html'), 'utf8');
    const js = fs.readFileSync(require.resolve('../static/js/dashboard.js'), 'utf8');
    assert.doesNotMatch(html, /https?:\/\//);
    assert.doesNotMatch(js, /innerHTML|localStorage|sessionStorage/);
    assert.match(html, /role="status"/);
});

test('saved scan history uses authenticated pagination and safe text', async () => {
    let requested;
    const {app} = fixture(async (path, options) => {
        requested = {path, options};
        return response({scans: [{scan_id: 'saved', scan_name: '<script>bad</script>', status: 'completed'}], total: 40});
    });
    app.token = 'fixture-token'; app.historyOffset = 25;
    await app.loadHistory();
    assert.equal(requested.path, '/api/scans?limit=25&offset=25');
    assert.equal(requested.options.headers.Authorization, 'Bearer fixture-token');
    assert.equal(app.el('scanHistory').children[0].textContent, '<script>bad</script> / completed / saved');
    assert.equal(app.el('previousHistoryBtn').disabled, false);
    app.logout();
    assert.equal(app.el('scanHistory').children.length, 0);
});

test('default fetch adapter does not bind native fetch to the controller', async () => {
    const original = global.fetch;
    global.fetch = function () {
        assert.equal(this, globalThis);
        return Promise.resolve(response({success: true}));
    };
    try {
        const {app} = fixture();
        app.token = 'fixture-token';
        assert.deepEqual(await app.request('/api/agents'), {success: true});
    } finally { global.fetch = original; }
});

test('template lists use authenticated bounded pagination and safe text', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        return response({templates: [savedTemplate({scan_name: '<script>bad</script>'})], total: 60});
    });
    app.token = 'fixture-token'; app.templateOffset = 25;
    await app.loadTemplates();
    assert.equal(calls[0].path, '/api/templates?limit=25&offset=25');
    assert.equal(calls[0].options.headers.Authorization, 'Bearer fixture-token');
    assert.equal(app.el('templateList').children[0].textContent, '<script>bad</script> / revision 3');
    assert.equal(app.el('previousTemplatesBtn').disabled, false);
    assert.equal(app.el('nextTemplatesBtn').disabled, false);
    app.templateOffset = 100000;
    await app.loadTemplates();
    assert.equal(app.el('nextTemplatesBtn').disabled, true);
    app.el('nextTemplatesBtn').handlers.click();
    assert.equal(app.templateOffset, 100000);
});

test('template lists reject oversized and malformed pages without rendering', async () => {
    for (const data of [{templates: Array.from({length: 26}, () => savedTemplate()), total: 26},
        {templates: [savedTemplate()], total: -1}, {templates: [savedTemplate({revision: 0})], total: 1}]) {
        const {app} = fixture(async () => response(data));
        app.token = 'fixture-token';
        await app.loadTemplates();
        assert.equal(app.el('templateList').children.length, 0);
        assert.match(app.el('notice').textContent, /invalid template/);
    }
});

test('new template list request supersedes an older page', async () => {
    const replies = [];
    const {app} = fixture(() => new Promise(done => replies.push(done)));
    app.token = 'fixture-token';
    const old = app.loadTemplates();
    app.templateOffset = 25;
    const current = app.loadTemplates();
    replies[1](response({templates: [savedTemplate({id: 'new', scan_name: 'New page'})], total: 26}));
    await current;
    replies[0](response({error: 'Old page failed'}, 500));
    await old;
    assert.equal(app.el('templateList').children[0].value, 'new');
    assert.doesNotMatch(app.el('notice').textContent, /Old page/);
});

test('save current form creates a template without admitting or polling a scan', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        return response(path.includes('?') ? {templates: [savedTemplate()], total: 1} : {template: savedTemplate()}, 201);
    });
    app.token = 'fixture-token'; app.el('scanName').value = 'Fixture';
    app.el('scanType').value = 'discovery_only'; app.el('networkRanges').value = '192.0.2.1';
    await app.saveTemplate();
    assert.equal(calls[0].path, '/api/templates');
    assert.equal(calls[0].options.method, 'POST');
    assert.deepEqual(JSON.parse(calls[0].options.body), {scan_name: 'Fixture', scan_type: 'discovery_only',
        target_scope: {network_ranges: ['192.0.2.1'], domains: [], repositories: [], traffic_sources: []}, scan_config: {}});
    assert.equal(app.scanId, null);
    assert.equal(app.timer, null);
    assert.equal(app.template.revision, 3);
    assert.equal(app.el('templateEditorView').hidden, false);
    assert.equal(calls.length, 2);
});

test('save form preserves security-only source models and excludes new targets', async () => {
    let body;
    const {app} = fixture(async (path, options) => {
        if (options.method === 'POST') body = JSON.parse(options.body);
        return response(path.includes('?') ? {templates: [], total: 0} : {template: savedTemplate()});
    });
    app.token = 'fixture-token'; app.el('scanName').value = 'Source recipe';
    app.el('scanType').value = 'security_only'; app.el('sourceScanId').value = 'source';
    app.el('modelOverrides').value = '{"asset":"fixture-model"}';
    app.el('networkRanges').value = 'not-used.example.test';
    await app.saveTemplate();
    assert.deepEqual(body.target_scope, {});
    assert.deepEqual(body.scan_config, {source_scan_id: 'source', model_overrides: {asset: 'fixture-model'}});
});

test('invalid source models and missing targets cannot save or scan', async () => {
    for (const action of ['saveTemplate', 'startScan']) {
        const {app} = fixture(async () => { throw new Error('Unexpected network call'); });
        app.token = 'fixture-token'; app.el('scanType').value = 'security_only';
        await app[action](event);
        assert.match(app.el('notice').textContent, /completed source scan ID/);
        app.el('sourceScanId').value = 'source'; app.el('modelOverrides').value = '[]';
        await app[action](event);
        assert.match(app.el('notice').textContent, /Model selections must/);
        app.el('scanType').value = 'discovery_only';
        await app[action](event);
        assert.match(app.el('notice').textContent, /at least one target/);
    }
});

test('complete definition editor preserves advanced targets and source models on update', async () => {
    const calls = [];
    const definition = savedTemplate({scan_type: 'security_only', target_scope: {},
        scan_config: {source_scan_id: 'source', model_overrides: {asset: 'model'}, timeout_seconds: 180, advanced_future_field: false}});
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        return response(path.includes('?') ? {templates: [], total: 0} : {template: {...definition, revision: 4}});
    });
    app.token = 'fixture-token'; app.showTemplate(definition);
    await app.updateTemplate();
    const body = JSON.parse(calls[0].options.body);
    assert.deepEqual(body.scan_config, definition.scan_config);
    assert.equal(body.revision, 3);
    assert.equal(calls[0].options.method, 'PUT');
    assert.equal(app.template.revision, 4);
    assert.equal(app.scanId, null);
    app.showTemplate(savedTemplate());
    assert.equal(JSON.parse(app.el('templateEditor').value).target_scope.active_probe, false);
});

test('update rejects malformed JSON and unsupported top-level fields without discarding editor text', async () => {
    const {app} = fixture(async () => { throw new Error('Unexpected network call'); });
    app.token = 'fixture-token'; app.showTemplate(savedTemplate());
    for (const text of ['{bad', '[]', '{"revision":4}', '{}']) {
        app.el('templateEditor').value = text;
        await app.updateTemplate();
        assert.equal(app.el('templateEditor').value, text);
        assert.match(app.el('notice').textContent, /valid JSON|four displayed fields/);
    }
});

test('stale revision keeps editor changes and does not retry automatically', async () => {
    for (const action of ['updateTemplate', 'runTemplate']) {
        let calls = 0;
        const {app} = fixture(async () => { calls += 1; return response({error: 'stale'}, 409); });
        app.token = 'fixture-token'; app.showTemplate(savedTemplate());
        const original = app.el('templateEditor').value;
        await app[action]();
        assert.equal(calls, 1);
        assert.equal(app.template.revision, 3);
        assert.equal(app.el('templateEditor').value, original);
        assert.match(app.el('notice').textContent, /Template changed.*Reload/);
        assert.equal(app.el('runTemplateBtn').disabled, false);
    }
});

test('missing or foreign template uses the same unavailable notice', async () => {
    for (const action of ['openTemplate', 'updateTemplate', 'runTemplate', 'deleteTemplate']) {
        const {app} = fixture(async () => response({error: 'not found'}, 404));
        app.token = 'fixture-token'; app.showTemplate(savedTemplate());
        await app[action]('recipe');
        assert.match(app.el('notice').textContent, /missing or unavailable to this organization/);
        assert.equal(app.scanId, null);
    }
});

test('policy, source and queue errors are displayed as text without admitting a scan', async () => {
    for (const status of [400, 403, 429, 500]) {
        const {app} = fixture(async () => response({error: '<script>fixture failure</script>'}, status));
        app.token = 'fixture-token'; app.showTemplate(savedTemplate());
        await app.runTemplate();
        assert.equal(app.el('notice').textContent, '<script>fixture failure</script>');
        assert.equal(app.scanId, null);
        assert.equal(app.templateBusy, false);
    }
});

test('manual run pins saved revision and ignores unsaved JSON before selecting admitted scan', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        return response(options.method === 'POST' ? {scan_id: 'admitted'} : {scans: [], total: 0}, 202);
    });
    app.token = 'fixture-token'; app.showTemplate(savedTemplate({id: 'recipe/id'}));
    app.el('templateEditor').value = '{not saved';
    app.selectScan = async id => { app.scanId = id; };
    await app.runTemplate();
    assert.equal(calls[0].path, '/api/templates/recipe%2Fid/run');
    assert.deepEqual(JSON.parse(calls[0].options.body), {revision: 3});
    assert.equal(app.scanId, 'admitted');
    assert.equal(app.el('templateEditor').value, '{not saved');
});

test('delete removes only the recipe and keeps selected scan state unchanged', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => { calls.push({path, options}); return response({templates: [], total: 0}); });
    app.token = 'fixture-token'; app.scanId = 'admitted'; app.showTemplate(savedTemplate());
    await app.deleteTemplate();
    assert.equal(calls[0].path, '/api/templates/recipe');
    assert.equal(calls[0].options.method, 'DELETE');
    assert.equal(app.scanId, 'admitted');
    assert.equal(app.template, null);
    assert.equal(app.el('templateEditor').value, '');
    assert.equal(app.el('templateEditorView').hidden, true);
    assert.ok(calls.every(call => !call.path.includes('/cancel')));
});

test('all template requests are suppressed after logout including late errors', async () => {
    for (const action of ['loadTemplates', 'openTemplate', 'updateTemplate', 'runTemplate', 'deleteTemplate', 'saveTemplate']) {
        for (const failure of [false, true]) {
            let resolve;
            const {app} = fixture(() => new Promise(done => { resolve = done; }));
            app.token = 'fixture-token'; app.showTemplate(savedTemplate());
            app.el('scanType').value = 'discovery_only'; app.el('networkRanges').value = '192.0.2.1';
            const pending = app[action]('recipe');
            app.logout();
            resolve(response(failure ? {error: 'Old failure'} : {template: savedTemplate(), templates: [savedTemplate()], total: 1, scan_id: 'late'}, failure ? 500 : 200));
            await pending;
            assert.equal(app.el('notice').textContent, 'Signed out.');
            assert.equal(app.el('templateList').children.length, 0);
            assert.equal(app.el('templateEditor').value, '');
            assert.equal(app.el('templateIdentity').textContent, '');
            assert.equal(app.el('templateEditorView').hidden, true);
            assert.equal(app.el('templateControls').disabled, true);
            assert.equal(app.template, null);
            assert.equal(app.templateHasNext, false);
            assert.equal(app.scanId, null);
        }
    }
});

test('pending template actions block duplicate mutations and restore buttons', async () => {
    let resolve; let calls = 0;
    const {app} = fixture(() => { calls += 1; return new Promise(done => { resolve = done; }); });
    app.token = 'fixture-token'; app.showTemplate(savedTemplate());
    const pending = app.updateTemplate();
    assert.equal(app.el('updateTemplateBtn').disabled, true);
    assert.equal(app.el('templateEditor').disabled, true);
    await app.runTemplate(); await app.deleteTemplate();
    assert.equal(calls, 1);
    resolve(response({error: 'rejected'}, 403));
    await pending;
    assert.equal(app.el('updateTemplateBtn').disabled, false);
    assert.equal(app.el('templateEditor').disabled, false);
});

test('template run responses and errors cannot override a newer selected scan', async () => {
    for (const failure of [false, true]) {
        let resolve;
        const {app} = fixture(() => new Promise(done => { resolve = done; }));
        app.token = 'fixture-token'; app.showTemplate(savedTemplate());
        const pending = app.runTemplate();
        app.selection += 1; app.scanId = 'newer'; app.notice('Newer scan selected.');
        resolve(response(failure ? {error: 'Old failure'} : {scan_id: 'old'}, failure ? 500 : 202));
        await pending;
        assert.equal(app.scanId, 'newer');
        assert.equal(app.el('notice').textContent, 'Newer scan selected.');
        assert.equal(app.templateBusy, false);
    }
});

test('loading or saving another recipe cannot silently discard dirty editor text', async () => {
    let calls = 0;
    const {app} = fixture(async () => { calls += 1; return response({templates: [savedTemplate()], total: 1}); });
    app.token = 'fixture-token'; app.showTemplate(savedTemplate());
    const original = app.el('templateEditor').value;
    app.el('templateEditor').value = '{dirty text';
    await app.openTemplate('another'); await app.saveTemplate();
    assert.equal(calls, 0);
    assert.equal(app.el('templateEditor').value, '{dirty text');
    assert.match(app.el('notice').textContent, /Unsaved editor changes/);
    await app.loadTemplates();
    assert.equal(app.el('templateEditor').value, '{dirty text');
    app.el('discardTemplateBtn').handlers.click();
    assert.equal(app.el('templateEditor').value, original);
    assert.equal(app.template.revision, 3);
    assert.equal(calls, 1);
});

test('failed initial template list leaves authenticated refresh and form save usable', async () => {
    let fail = true;
    const {app} = fixture(async path => {
        if (path === '/api/auth/token') return response({token: 'fixture-token'});
        if (path.startsWith('/api/templates?')) return fail ? response({error: 'Template service unavailable'}, 503) :
            response({templates: [savedTemplate()], total: 1});
        return response({scans: [], total: 0});
    });
    app.el('operatorKey').value = 'fixture-key';
    await app.login(event);
    assert.equal(app.token, 'fixture-token');
    assert.equal(app.el('refreshTemplatesBtn').disabled, false);
    assert.equal(app.el('saveTemplateBtn').disabled, false);
    assert.match(app.el('notice').textContent, /Template service unavailable/);
    fail = false;
    await app.loadTemplates();
    assert.equal(app.el('templateList').children.length, 1);
    app.logout();
    assert.equal(app.el('refreshTemplatesBtn').disabled, true);
    assert.equal(app.el('saveTemplateBtn').disabled, true);
});

test('check execution and outcome remain distinct, with safe reasons and cloud identity', () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const checks = [
        {rule_id: hostile, status: 'completed', outcome: 'inconclusive', responses_evaluated: 2},
        {rule_id: 'tenant', status: 'skipped', outcome: 'not_evaluated', responses_evaluated: 0, reason: hostile},
        {rule_id: 'prompt', status: 'failed', outcome: 'confirmed', responses_evaluated: 1, reason: 'One request failed'},
    ];
    const report = checkedReport(checks);
    report.agents[0].metadata = {resource_id: hostile};
    const {app} = fixture();
    app.renderReport(report);
    const rendered = texts(app.el('assetList'));
    assert.ok(rendered.includes(hostile));
    assert.ok(rendered.includes(`Cloud resource: ${hostile}`));
    assert.ok(rendered.includes('completed / inconclusive'));
    assert.ok(rendered.includes('failed / confirmed'));
    assert.ok(rendered.includes('Responses evaluated: 0'));
    assert.ok(rendered.includes('Risk: Not assessed'));
    assert.match(app.el('checkSummary').textContent, /1 completed \/ 1 skipped \/ 1 failed/);
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
});

test('historical scores without check evidence do not look like a current assessment', () => {
    const {app} = fixture();
    app.renderReport({status: 'completed', agents: [{id: 'legacy', name: 'Legacy', risk_score: 0}],
        summary: {overall_risk_score: 0}});
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
    assert.match(app.el('checkSummary').textContent, /Check evidence unavailable/);
    assert.ok(texts(app.el('assetList')).includes('Risk: Not assessed'));
    assert.ok(texts(app.el('assetList')).includes('Check evidence unavailable for this report.'));
});

test('modern conclusive evidence can display the stored assessment score', () => {
    const {app} = fixture();
    app.renderReport(checkedReport([{rule_id: 'prompt', status: 'completed', outcome: 'passed', responses_evaluated: 1, requests_attempted: 1}], 0));
    assert.equal(app.el('riskScore').textContent, '0.0 / 100');
    assert.ok(texts(app.el('assetList')).includes('Risk: 0.0 / 100'));
});

test('inconclusive checks cannot make zero risk look assessed', () => {
    const {app} = fixture();
    app.renderReport(checkedReport([{rule_id: 'prompt', status: 'completed', outcome: 'inconclusive', responses_evaluated: 1, requests_attempted: 1}], 0));
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
    assert.ok(texts(app.el('assetList')).includes('Risk: Not assessed'));
});

test('large check lists render in bounded pages with the complete export still available', () => {
    const {app} = fixture();
    const card = new Element();
    const checks = Array.from({length: 140}, (_, index) => ({rule_id: `rule-${index}`, status: 'skipped', outcome: 'not_evaluated', responses_evaluated: 0}));
    app.renderChecks(card, checks);
    const details = card.children[0];
    const list = details.children[1];
    const more = details.children[2];
    assert.equal(list.children.length, 18);
    assert.equal(more.hidden, false);
    for (let index = 0; index < 5; index += 1) more.click();
    assert.equal(list.children.length, 100);
    assert.equal(more.hidden, true);
    assert.ok(texts(details).some(text => text.includes('Showing 100 of 140 checks')));
});

test('audit uses authenticated cursor pagination, ordered safe text, and refresh', async () => {
    const calls = [];
    const hostile = '<script>alert(1)</script>';
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        if (path.endsWith('after=100')) return response({events: [{...auditEvent(101), event: hostile, status: hostile}], next_after: 101});
        return response({events: Array.from({length: 100}, (_, index) => auditEvent(index + 1)), next_after: 100});
    });
    app.token = 'fixture-token'; app.scanId = 'fixture';
    await app.loadAudit(true);
    assert.equal(calls[0].path, '/api/scans/fixture/audit?limit=100&after=0');
    assert.equal(calls[0].options.headers.Authorization, 'Bearer fixture-token');
    assert.equal(app.el('auditList').children.length, 100);
    assert.equal(app.el('moreAuditBtn').disabled, false);
    await app.loadAudit();
    assert.equal(app.el('auditList').children.length, 101);
    assert.ok(texts(app.el('auditList')).includes(hostile));
    assert.equal(app.el('moreAuditBtn').disabled, true);
    await app.loadAudit(true);
    assert.equal(app.el('auditList').children.length, 100);
    assert.equal(app.auditCursor, 100);
});

test('audit timeline stops after 500 events without another request', async () => {
    let calls = 0;
    const {app} = fixture(async path => {
        calls += 1;
        const after = Number(path.split('after=')[1]);
        return response({events: Array.from({length: 100}, (_, index) => auditEvent(after + index + 1)), next_after: after + 100});
    });
    app.token = 'fixture-token'; app.scanId = 'fixture';
    for (let index = 0; index < 6; index += 1) await app.loadAudit();
    assert.equal(calls, 5);
    assert.equal(app.el('auditList').children.length, 500);
    assert.match(app.el('auditNotice').textContent, /Showing 500 events/);
});

test('late audit response cannot populate another selected scan', async () => {
    let resolve;
    const {app} = fixture(() => new Promise(done => { resolve = done; }));
    app.token = 'fixture-token'; app.scanId = 'first';
    const loading = app.loadAudit();
    app.selection += 1; app.scanId = 'second'; app.clearAudit();
    resolve(response({events: [auditEvent(1)], next_after: 1}));
    await loading;
    assert.equal(app.el('auditList').children.length, 0);
    assert.equal(app.auditCursor, 0);
    assert.equal(app.el('auditView').hidden, true);
});

test('logout clears audit and rejects late audit responses and errors', async () => {
    for (const reject of [false, true]) {
        let resolve;
        const {app} = fixture(() => new Promise(done => { resolve = done; }));
        app.token = 'fixture-token'; app.scanId = 'first';
        app.el('auditList').appendChild(new Element());
        const loading = app.loadAudit();
        app.logout();
        resolve(response(reject ? {error: 'Old failure'} : {events: [auditEvent(1)], next_after: 1}, reject ? 500 : 200));
        await loading;
        assert.equal(app.el('auditList').children.length, 0);
        assert.equal(app.el('auditNotice').textContent, '');
        assert.equal(app.el('notice').textContent, 'Signed out.');
    }
});

test('new audit refresh supersedes an older page request', async () => {
    const replies = [];
    const {app} = fixture(() => new Promise(done => replies.push(done)));
    app.token = 'fixture-token'; app.scanId = 'fixture';
    const older = app.loadAudit();
    const refresh = app.loadAudit(true);
    replies[1](response({events: [auditEvent(2)], next_after: 2}));
    await refresh;
    replies[0](response({events: [auditEvent(1)], next_after: 1}));
    await older;
    assert.equal(app.el('auditList').children.length, 1);
    assert.equal(app.auditCursor, 2);
});

test('audit errors and invalid cursors do not disable legitimate report exports', async () => {
    for (const bad of [response({error: 'Audit unavailable'}, 500), response({events: [auditEvent(1)], next_after: 0})]) {
        const {app} = fixture(async path => path.includes('/audit?') ? bad :
            response({results: {pipeline: checkedReport([])}}));
        app.token = 'fixture-token'; app.scanId = 'fixture';
        await app.loadResults(app.selection);
        await app.loadAudit(true);
        assert.equal(app.el('jsonBtn').disabled, false);
        assert.equal(app.el('sarifBtn').disabled, false);
        assert.match(app.el('auditNotice').textContent, /Audit history unavailable/);
        assert.equal(app.el('refreshAuditBtn').disabled, false);
    }
});

test('stale selected-scan failures cannot overwrite the current notice', async () => {
    for (const method of ['cancel', 'download']) {
        let resolve;
        const {app} = fixture(() => new Promise(done => { resolve = done; }));
        app.token = 'fixture-token'; app.scanId = 'first';
        const pending = app[method]('json');
        app.selection += 1; app.scanId = 'second'; app.notice('Second scan selected');
        resolve(response({error: 'First scan unavailable'}, 404));
        await pending;
        assert.equal(app.el('notice').textContent, 'Second scan selected');
    }
});

test('selecting a scan loads its report despite an unavailable audit route', async () => {
    const {app} = fixture(async path => {
        if (path.endsWith('/status')) return response({status: 'completed', progress: 100});
        if (path.endsWith('/results')) return response({results: {pipeline: checkedReport([])}});
        return response({error: 'Audit unavailable'}, 500);
    });
    app.token = 'fixture-token';
    await app.selectScan('fixture');
    assert.equal(app.el('reportView').hidden, false);
    assert.equal(app.el('jsonBtn').disabled, false);
    assert.match(app.el('auditNotice').textContent, /Audit history unavailable/);
    app.logout();
    assert.equal(app.el('reportNote').textContent, '');
    assert.equal(app.el('checkSummary').textContent, '');
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
});

test('switching scans clears audit and an earlier selection cannot restore it', async () => {
    let firstReply;
    const {app} = fixture(path => path.includes('/first/') ? new Promise(done => { firstReply = done; }) :
        Promise.resolve(response({events: [auditEvent(2)], next_after: 2})));
    app.token = 'fixture-token';
    app.poll = async () => {};
    const first = app.selectScan('first');
    await app.selectScan('second');
    firstReply(response({events: [auditEvent(1)], next_after: 1}));
    await first;
    assert.equal(app.scanId, 'second');
    assert.equal(app.el('selectedScanId').textContent, 'second');
    assert.equal(app.auditCursor, 2);
    assert.equal(app.el('auditList').children.length, 1);
});
