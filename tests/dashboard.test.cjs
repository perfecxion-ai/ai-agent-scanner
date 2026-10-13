const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {AIAgentScanner, TERMINAL_STATES} = require('../static/js/dashboard.js');

class Element {
    constructor(tag = 'div') { this.tagName = tag; this.children = []; this.value = ''; this.textContent = ''; this.disabled = false; this.hidden = false; }
    addEventListener() {}
    appendChild(child) { this.children.push(child); return child; }
    replaceChildren(...children) { this.children = children; }
    click() { this.clicked = true; }
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
