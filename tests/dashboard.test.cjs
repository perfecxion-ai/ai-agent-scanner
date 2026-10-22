const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {AIAgentScanner, TERMINAL_STATES, groupFindingOccurrences} = require('../static/js/dashboard.js');

class Element {
    constructor(tag = 'div', ownerDocument = null) { this.tagName = tag; this.ownerDocument = ownerDocument; this.children = []; this.value = ''; this.textContent = ''; this.disabled = false; this.hidden = false; this.handlers = {}; this.attributes = {}; }
    addEventListener(event, handler) { this.handlers[event] = handler; }
    appendChild(child) { this.children.push(child); return child; }
    replaceChildren(...children) { this.children = children; }
    click() { this.clicked = true; if (this.handlers.click) this.handlers.click(); }
    focus() { if (!this.disabled) { this.focused = true; if (this.ownerDocument) this.ownerDocument.activeElement = this; } }
    setAttribute(name, value) { this.attributes[name] = value; }
    set innerHTML(value) { throw new Error('Unsafe HTML rendering'); }
}

function fixture(fetcher) {
    const elements = new Map();
    const doc = {activeElement: null, getElementById(id) { if (!elements.has(id)) elements.set(id, new Element('div', doc)); return elements.get(id); },
                 createElement(tag) { return new Element(tag, doc); }};
    const app = new AIAgentScanner(doc, fetcher);
    return {app, doc};
}
const response = (data, status = 200) => ({ok: status >= 200 && status < 300, status, json: async () => data});
const event = {preventDefault() {}};
const texts = node => [node.textContent, ...node.children.flatMap(texts)];
const checkedReport = (checks, score = null) => ({status: 'completed', check_schema_version: '1.0',
    risk_assessment_status: score === null ? 'not_assessed' : 'completed',
    agents: [{id: 'asset', name: 'Fixture', security_status: 'completed', risk_score: score,
        risk_scoring_policy: 'severity-floor-v2', checks, vulnerabilities: []}],
    security_results: [], summary: {overall_risk_score: score}});
const auditEvent = id => ({id, event: 'claim', previous_status: 'queued', status: 'running', created_at: '2026-10-13T10:00:00'});
const savedTemplate = (changes = {}) => ({id: 'recipe', revision: 3, scan_name: 'Lab recipe', scan_type: 'discovery_only',
    target_scope: {network_ranges: ['192.0.2.0/28'], active_probe: false}, scan_config: {timeout_seconds: 120}, ...changes});
const savedSchedule = (changes = {}) => ({id: 'schedule', template_id: 'recipe', template_revision: 3, interval_seconds: 60,
    total_runs: 4, admitted_runs: 0, revision: 2, state: 'disabled', pause_reason: null, outstanding_scan_id: null,
    next_due_at: null, ...changes});
const occurrence = (ordinal = 1, changes = {}) => ({ordinal, scan_id: `scan-${ordinal}`, created_at: '2026-10-13T10:00:00+00:00', ...changes});
function promptReport(counts = [3, 3, 3, 3, 2, 2, 2]) {
    const categories = ['system_prompt_extraction', 'instruction_bypass', 'role_manipulation',
        'dan_jailbreak', 'context_manipulation', 'injection_via_encoding', 'payload_injection'];
    const checks = counts.map((count, index) => ({rule_id: `prompt_injection.${categories[index]}`,
        probe_id: `prompt_injection.${categories[index]}.sample`, probe_version: '1:synthetic',
        evidence_context_id: 'fixture-policy-v1', status: 'completed', outcome: 'confirmed',
        requests_attempted: count, responses_evaluated: count}));
    const findings = counts.flatMap((count, index) => Array.from({length: count}, (_, sample) => ({
        id: `occurrence-${index}-${sample}`, agent_id: 'fixture-asset', vulnerability_type: 'prompt_injection',
        category: categories[index], severity: 'high', evidence_status: 'confirmed', title: 'Protected System Canary Disclosure',
        description: 'Configured protected canary was returned.', remediation: 'Review the protected instruction boundary.',
        rule_id: checks[index].rule_id, probe_id: checks[index].probe_id, probe_version: checks[index].probe_version,
        evidence_context_id: checks[index].evidence_context_id, payload: `Synthetic attack ${sample}`,
        response_excerpt: '[GENERATED_TEXT_OMITTED]', timestamp: `2026-10-21T12:00:0${sample}Z`, confidence: 0.95})));
    return {schema_version: '1.0', check_schema_version: '1.0', status: 'completed', scan_type: 'full',
        risk_assessment_status: 'completed', summary: {overall_risk_score: 70, vulnerabilities_found: findings.length},
        security_results: [], agents: [{id: 'fixture-asset', name: 'Synthetic fixture', provider: 'openai-compatible',
            model: 'fixture-model', security_status: 'completed', risk_score: 70,
            risk_scoring_policy: 'severity-floor-v2', checks, vulnerabilities: findings}]};
}
function reviewPin(app) {
    app.showTemplate(savedTemplate());
    app.el('reviewScheduleTemplate').checked = true;
    app.el('scheduleInterval').value = '60';
    app.el('scheduleRuns').value = '4';
    app.scheduleButtons();
}

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

test('terminal announcements are concise, conservative, and do not repeat or rerender on polling', async () => {
    for (const status of TERMINAL_STATES) {
        let reports = 0;
        const {app, doc} = fixture(async path => {
            if (path.endsWith('/status')) return response({status, progress: 100});
            reports += 1;
            return response({results: {pipeline: checkedReport([{rule_id: 'fixture', status: 'skipped', outcome: 'not_evaluated'}])}});
        });
        app.token = 'fixture-token'; app.scanId = 'fixture';
        app.el('openScanId').focus();
        await app.poll();
        const announcement = app.el('scanAnnouncement').textContent;
        assert.match(announcement, /Report available\. Review incomplete checks and evidence\./);
        assert.ok(announcement.length < 150);
        assert.equal(doc.activeElement, app.el('openScanId'));
        const card = app.el('assetList').children[0];
        const region = card.children.find(child => child.tagName === 'details').children[1];
        region.focus();
        await app.poll();
        assert.equal(reports, 1);
        assert.equal(app.el('assetList').children[0], card);
        assert.equal(doc.activeElement, region);
        assert.equal(app.el('scanAnnouncement').textContent, announcement);
        app.notice('Another operator action.');
        await app.poll();
        assert.equal(app.el('notice').textContent, 'Another operator action.');
    }
});

test('all terminal states announce unavailable or historical evidence without claiming assessment', async () => {
    for (const status of TERMINAL_STATES) {
        for (const historical of [false, true]) {
            let failed = !historical;
            const {app} = fixture(async path => path.endsWith('/status') ? response({status}) :
                failed ? response({error: 'Results unavailable'}, 503) : response({results: {pipeline: historical ? null : checkedReport([])}}));
            app.token = 'fixture-token'; app.scanId = 'fixture';
            app.clearReport();
            await app.poll();
            const announcement = app.el('scanAnnouncement').textContent;
            assert.match(announcement, /Testing completeness is unverified\./);
            assert.match(announcement, historical ? /No versioned report/ : /Report unavailable/);
            assert.equal(app.el('jsonBtn').disabled, true);
            failed = false;
            await app.poll();
            if (historical) assert.equal(app.el('scanAnnouncement').textContent, announcement);
            else {
                assert.match(app.el('scanAnnouncement').textContent, /Report available\./);
                assert.doesNotMatch(app.el('scanAnnouncement').textContent, /unavailable|unverified/);
                assert.equal(app.el('jsonBtn').disabled, false);
                const recovered = app.el('scanAnnouncement').textContent;
                await app.poll();
                assert.equal(app.el('scanAnnouncement').textContent, recovered);
            }
        }
    }
});

test('nonterminal updates do not announce completion or move focus', async () => {
    const {app, doc} = fixture(async () => response({status: 'running', progress: 50}));
    app.token = 'fixture-token'; app.scanId = 'fixture';
    app.el('operatorKey').focus();
    await app.poll();
    clearTimeout(app.timer);
    assert.equal(app.el('scanAnnouncement').textContent, '');
    assert.equal(doc.activeElement, app.el('operatorKey'));
});

test('selecting a different scan clears only historical report-owned notices', async () => {
    for (const unrelated of [false, true]) {
        const {app} = fixture(async path => {
            if (path.includes('/audit?')) return response({events: [], next_after: 0});
            if (path.endsWith('/status')) return response({status: path.includes('/historical/') ? 'completed' : 'partial'});
            return response({results: {pipeline: path.includes('/historical/') ? null : {...checkedReport([]), status: 'partial'}}});
        });
        app.token = 'fixture-token';
        await app.selectScan('historical');
        assert.match(app.el('notice').textContent, /no versioned report/);
        if (unrelated) app.notice('Template revision conflict. Reload before editing.', true);
        await app.selectScan('partial');
        assert.equal(app.el('notice').textContent, unrelated ? 'Template revision conflict. Reload before editing.' : '');
        assert.equal(app.el('notice').className, unrelated ? 'notice error' : 'notice');
        assert.match(app.el('scanAnnouncement').textContent, /partial results\. Report available/);
    }
});

test('report recovery clears its own fetch error but preserves newer unrelated notices', async () => {
    for (const unrelated of [false, true]) {
        let fail = true;
        const {app} = fixture(async path => path.endsWith('/status') ? response({status: 'completed'}) :
            fail ? response({error: 'Report temporarily unavailable'}, 503) : response({results: {pipeline: checkedReport([])}}));
        app.token = 'fixture-token'; app.scanId = 'fixture';
        await app.poll();
        assert.equal(app.el('notice').textContent, 'Report temporarily unavailable');
        assert.equal(app.noticeOwner, 'scan-report');
        if (unrelated) app.notice('Schedule policy review required.', true);
        fail = false;
        await app.poll();
        assert.equal(app.el('notice').textContent, unrelated ? 'Schedule policy review required.' : '');
        assert.equal(app.el('notice').className, unrelated ? 'notice error' : 'notice');
        assert.match(app.el('scanAnnouncement').textContent, /Report available/);
    }
});

test('report notice reset does not clear a newer unrelated message even when its text is identical', () => {
    const {app} = fixture();
    app.notice('Temporarily unavailable', true, 'scan-report');
    app.notice('Temporarily unavailable', true);
    app.clearReport();
    assert.equal(app.el('notice').textContent, 'Temporarily unavailable');
    app.logout();
    assert.equal(app.el('notice').textContent, 'Signed out.');
    assert.equal(app.noticeOwner, null);
});

test('stale terminal results and failures cannot announce or focus after selection or logout', async () => {
    for (const logout of [false, true]) {
        for (const fail of [false, true]) {
            let reply;
            const {app, doc} = fixture(path => path.endsWith('/status') ? Promise.resolve(response({status: 'completed'})) :
                new Promise(done => { reply = done; }));
            app.token = 'fixture-token'; app.scanId = 'first';
            const pending = app.poll();
            for (let attempt = 0; attempt < 5 && !reply; attempt += 1) await Promise.resolve();
            assert.ok(reply);
            if (logout) app.logout();
            else { app.selection += 1; app.scanId = 'second'; app.clearReport(); app.el('scanAnnouncement').textContent = ''; app.el('openScanId').focus(); }
            const focused = doc.activeElement;
            reply(fail ? response({error: 'Old result error'}, 503) : response({results: {pipeline: checkedReport([])}}));
            await pending;
            assert.equal(app.el('scanAnnouncement').textContent, '');
            assert.equal(doc.activeElement, focused);
            assert.equal(app.el('assetList').children.length, 0);
        }
    }
});

test('401 results clear terminal announcements and protected report state', async () => {
    const {app, doc} = fixture(async path => path.endsWith('/status') ? response({status: 'completed'}) : response({error: 'Expired'}, 401));
    app.token = 'fixture-token'; app.scanId = 'fixture';
    app.el('scanAnnouncement').textContent = 'Old terminal state';
    await app.poll();
    assert.equal(app.token, null);
    assert.equal(app.el('scanAnnouncement').textContent, '');
    assert.equal(app.el('assetList').children.length, 0);
    assert.equal(doc.activeElement, app.el('operatorKey'));
});

test('selecting another scan resets report cache and permits its own terminal announcement', async () => {
    let reports = 0;
    const {app} = fixture(async path => {
        if (path.includes('/audit?')) return response({events: [], next_after: 0});
        if (path.endsWith('/status')) return response({status: path.includes('/first/') ? 'cancelled' : 'interrupted'});
        reports += 1;
        return response({results: {pipeline: checkedReport([])}});
    });
    app.token = 'fixture-token';
    await app.selectScan('first');
    assert.match(app.el('scanAnnouncement').textContent, /Scan cancelled/);
    await app.selectScan('second');
    assert.match(app.el('scanAnnouncement').textContent, /Scan interrupted/);
    assert.equal(reports, 2);
    app.logout();
    assert.equal(app.el('scanAnnouncement').textContent, '');
});

test('concurrent terminal result responses render and announce once without replacing focused records', async () => {
    for (const fail of [false, true]) {
        const replies = [];
        const {app, doc} = fixture(path => path.endsWith('/status') ? Promise.resolve(response({status: 'completed'})) :
            new Promise(done => replies.push(done)));
        app.token = 'fixture-token'; app.scanId = 'fixture';
        const first = app.poll();
        const second = app.poll();
        for (let attempt = 0; attempt < 5 && replies.length < 2; attempt += 1) await Promise.resolve();
        assert.equal(replies.length, 2);
        replies[1](response({results: {pipeline: checkedReport([{rule_id: 'current'}])}}));
        await second;
        const card = app.el('assetList').children[0];
        const region = card.children.find(child => child.tagName === 'details').children[1];
        region.focus();
        const announcement = app.el('scanAnnouncement').textContent;
        replies[0](fail ? response({error: 'Earlier result unavailable'}, 503) :
            response({results: {pipeline: checkedReport([{rule_id: 'earlier'}])}}));
        await first;
        assert.equal(app.el('assetList').children[0], card);
        assert.equal(doc.activeElement, region);
        assert.equal(app.el('scanAnnouncement').textContent, announcement);
        assert.ok(texts(region).includes('current'));
        assert.ok(!texts(region).includes('earlier'));
        assert.equal(app.el('scanStatus').textContent, 'completed');
    }
});

test('direct result loading caches only current successful responses and retries errors', async () => {
    let fail = true;
    let calls = 0;
    const {app} = fixture(async () => { calls += 1; return fail ? response({error: 'Unavailable'}, 503) :
        response({results: {pipeline: checkedReport([])}}); });
    app.token = 'fixture-token'; app.scanId = 'fixture'; app.clearReport();
    await assert.rejects(app.loadResults(app.selection), /Unavailable/);
    assert.equal(app.reportState, null);
    fail = false;
    assert.equal(await app.loadResults(app.selection), 'available');
    assert.equal(await app.loadResults(app.selection), 'available');
    assert.equal(calls, 2);
    app.clearReport();
    assert.equal(app.reportState, null);
    await app.loadResults(app.selection);
    assert.equal(calls, 3);
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
    assert.equal(app.el('findingList').children[0].children[0].children[0].textContent, hostile);
    assert.equal(app.el('observationList').children[0].children[0].textContent, 'Heuristic');
    assert.equal(app.el('assetList').children[0].children[0].textContent, hostile);
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
});

test('eighteen prompt occurrences form seven presentation groups without changing records or score', () => {
    const report = promptReport();
    const original = JSON.stringify(report);
    const groups = groupFindingOccurrences(report);
    assert.deepEqual(groups.map(group => group.occurrences.length), [3, 3, 3, 3, 2, 2, 2]);
    assert.equal(new Set(groups.flatMap(group => group.occurrences.map(item => item.id))).size, 18);
    assert.equal(groups[0].occurrences[0], report.agents[0].vulnerabilities[0]);
    const {app} = fixture();
    app.renderReport(report);
    assert.match(app.el('findingGroupingSummary').textContent, /^7 finding groups \/ 18 sample occurrences\./);
    assert.equal(app.el('findingCount').textContent, '18');
    assert.equal(app.el('findingList').children[0].children.length, 7);
    assert.equal(app.el('riskScore').textContent, '70.0 / 100');
    assert.match(app.el('checkSummary').textContent, /7 completed/);
    assert.equal(JSON.stringify(report), original);
});

for (const [field, value] of [['probe_version', '2:changed'], ['evidence_context_id', 'other-policy'],
    ['severity', 'medium'], ['control_status', 'different-boundary'], ['test_name', 'different-test'],
    ['path', '/different'], ['endpoint', 'https://different.invalid'], ['full_url', 'https://different.invalid'],
    ['title', 'Different title'], ['description', 'Different description'], ['remediation', 'Different remediation'],
    ['category', 'instruction_bypass'], ['vulnerability_type', 'different_type'], ['evidence_status', 'heuristic'],
    ['provider', 'different-provider'], ['model', 'different-model'], ['agent_id', 'different-asset']]) {
    test(`presentation grouping retains separate ${field} boundaries`, () => {
        const report = promptReport([3]);
        report.agents[0].vulnerabilities[2][field] = value;
        assert.deepEqual(groupFindingOccurrences(report).map(group => group.occurrences.length), [2, 1]);
    });
}

test('asset array entries remain separate even when every public identity is identical', () => {
    const report = promptReport([3]);
    report.agents.push(JSON.parse(JSON.stringify(report.agents[0])));
    assert.deepEqual(groupFindingOccurrences(report).map(group => group.occurrences.length), [3, 3]);
    report.agents[1].model = 'another-model';
    assert.deepEqual(groupFindingOccurrences(report).map(group => group.occurrences.length), [3, 3]);
});

test('changed valid probe versions have distinct matching-check groups', () => {
    const report = promptReport([3]);
    const changed = report.agents[0].vulnerabilities[2];
    changed.probe_version = '2:changed';
    report.agents[0].checks.push({...report.agents[0].checks[0], probe_version: changed.probe_version,
        requests_attempted: 1, responses_evaluated: 1});
    assert.deepEqual(groupFindingOccurrences(report).map(group => group.occurrences.length), [2, 1]);
});

test('malformed legacy null and primitive occurrences remain visible as singleton originals', () => {
    const {app} = fixture();
    const report = promptReport([3]);
    delete report.check_schema_version;
    report.agents[0].vulnerabilities = [null, 'legacy text', 3, false, ['legacy array']];
    const original = JSON.stringify(report);
    const groups = groupFindingOccurrences(report);
    assert.deepEqual(groups.map(group => group.occurrences), [[null], ['legacy text'], [3], [false], [['legacy array']]]);
    app.renderReport(report);
    assert.equal(app.el('findingCount').textContent, '5');
    assert.equal(app.el('findingList').children[0].children.length, 5);
    for (const card of app.el('findingList').children[0].children) {
        const details = card.children.find(child => child.tagName === 'details');
        details.open = true; details.handlers.toggle();
        assert.equal(details.children[1].children.filter(child => child.tagName === 'pre').length, 1);
    }
    assert.equal(JSON.stringify(report), original);
});

test('conflicting groups cannot each reuse the same evaluated-response count', () => {
    const report = promptReport([10]);
    report.agents[0].checks[0].responses_evaluated = 5;
    report.agents[0].vulnerabilities.slice(5).forEach(item => { item.severity = 'medium'; });
    assert.deepEqual(groupFindingOccurrences(report).map(group => group.occurrences.length), Array(10).fill(1));
});

test('a unique redacted occurrence ID does not join valid sample identities', () => {
    const report = promptReport([3]);
    report.agents[0].vulnerabilities[2].id = '[redacted]';
    assert.deepEqual(groupFindingOccurrences(report).map(group => group.occurrences.length), [2, 1]);
});

test('malformed singleton visible fields are bounded without altering raw text', () => {
    const {app} = fixture();
    const report = promptReport([3]);
    report.agents[0].vulnerabilities[2].title = 'x'.repeat(20000);
    report.agents[0].vulnerabilities[2].description = 'y'.repeat(20000);
    const original = JSON.stringify(report);
    app.renderReport(report);
    const cards = app.el('findingList').children[0].children;
    assert.equal(cards.length, 2);
    assert.ok(cards[1].children[0].textContent.length < 4200);
    assert.match(cards[1].children[0].textContent, /Preview truncated; download JSON/);
    assert.ok(cards[1].children.filter(node => node.tagName === 'p').every(node => node.textContent.length < 4200));
    assert.equal(JSON.stringify(report), original);
});

for (const mutation of ['historical', 'missing-context', 'redacted-context', 'redacted-version', 'missing-model',
    'missing-id', 'duplicate-id', 'missing-check', 'ambiguous-check', 'wrong-context-check', 'failed-check',
    'unmatched-check', 'invalid-count', 'overcount', 'object-path']) {
    test(`historical or malformed provenance remains ungrouped: ${mutation}`, () => {
        const report = promptReport([3]);
        const asset = report.agents[0];
        if (mutation === 'historical') delete report.check_schema_version;
        if (mutation === 'missing-context') asset.vulnerabilities.forEach(item => { delete item.evidence_context_id; });
        if (mutation === 'redacted-context') asset.vulnerabilities.forEach(item => { item.evidence_context_id = '[redacted]'; });
        if (mutation === 'redacted-version') {
            asset.vulnerabilities.forEach(item => { item.probe_version = '[redacted]'; });
            asset.checks[0].probe_version = '[redacted]';
        }
        if (mutation === 'missing-model') delete asset.model;
        if (mutation === 'missing-id') asset.vulnerabilities.forEach(item => { delete item.id; });
        if (mutation === 'duplicate-id') asset.vulnerabilities.forEach(item => { item.id = 'ambiguous'; });
        if (mutation === 'missing-check') asset.checks = [];
        if (mutation === 'ambiguous-check') asset.checks.push({...asset.checks[0]});
        if (mutation === 'wrong-context-check') asset.checks[0].evidence_context_id = 'other-context';
        if (mutation === 'failed-check') asset.checks[0].outcome = 'inconclusive';
        if (mutation === 'unmatched-check') asset.checks[0].probe_id = 'other-probe';
        if (mutation === 'invalid-count') asset.checks[0].requests_attempted = 0;
        if (mutation === 'overcount') asset.checks[0].responses_evaluated = 2;
        if (mutation === 'object-path') asset.vulnerabilities.forEach(item => { item.path = {}; });
        assert.deepEqual(groupFindingOccurrences(report).map(group => group.occurrences.length), [1, 1, 1]);
    });
}

test('failed execution with confirmed evidence may group without changing partial risk', () => {
    const report = promptReport([3]);
    report.status = report.risk_assessment_status = 'partial';
    report.agents[0].security_status = report.agents[0].checks[0].status = 'failed';
    const {app} = fixture();
    app.renderReport(report);
    assert.equal(groupFindingOccurrences(report).length, 1);
    assert.equal(app.el('riskScore').textContent, '70.0 / 100 (partial coverage)');
});

test('occurrence records are lazy, literal, preserved on reopen, and cleared on logout', () => {
    const {app, doc} = fixture();
    const report = promptReport([3]);
    const hostile = '<img src=x onerror=alert(1)>';
    report.agents[0].vulnerabilities.forEach(item => { item.title = hostile; item.payload = hostile; });
    app.renderReport(report);
    const card = app.el('findingList').children[0].children[0];
    const details = card.children.find(child => child.tagName === 'details');
    const list = details.children[1];
    assert.equal(list.children.length, 0);
    details.children[0].focus();
    details.open = true;
    details.handlers.toggle();
    assert.equal(doc.activeElement, details.children[0]);
    assert.equal(list.children.length, 6);
    assert.equal(card.children[0].textContent, hostile);
    assert.deepEqual(JSON.parse(list.children[1].textContent), report.agents[0].vulnerabilities[0]);
    details.open = false; details.handlers.toggle(); details.open = true; details.handlers.toggle();
    assert.equal(list.children.length, 6);
    app.logout();
    assert.equal(app.el('findingList').children.length, 0);
    assert.equal(app.el('findingGroupingSummary').textContent, '');
});

test('finding group pages use full-report counts and cap DOM with focus restoration', () => {
    const {app, doc} = fixture();
    const report = promptReport([3]);
    const baseline = report.agents[0];
    report.agents = Array.from({length: 110}, (_, index) => ({...baseline, id: `asset-${index}`,
        vulnerabilities: baseline.vulnerabilities.map(item => ({...item, agent_id: `asset-${index}`}))}));
    app.renderReport(report);
    assert.equal(app.el('findingCount').textContent, '330');
    assert.match(app.el('findingGroupingSummary').textContent, /^110 finding groups \/ 330 sample occurrences\./);
    const container = app.el('findingList');
    const [list, more, progress] = container.children;
    assert.equal(list.children.length, 18);
    assert.match(progress.textContent, /^18 of 110 finding groups shown/);
    more.focus();
    while (!more.hidden) more.click();
    assert.equal(list.children.length, 100);
    assert.equal(doc.activeElement, list);
    assert.match(texts(container).join(' '), /Showing 100 of 110 finding groups/);
    const count = container.children.length;
    more.click();
    assert.equal(container.children.length, count);
    const css = fs.readFileSync(require.resolve('../static/css/dashboard.css'), 'utf8');
    assert.match(css, /\.finding-groups:focus-visible,\.finding-occurrences:focus-visible\{outline:3px solid #3b9a88/);
    assert.equal(list.className, 'finding-groups');
});

test('occurrence previews page and truncate without changing complete export data', () => {
    const {app, doc} = fixture();
    const report = promptReport([110]);
    report.agents[0].vulnerabilities[0].payload = 'x'.repeat(20000);
    const original = JSON.stringify(report);
    app.renderReport(report);
    const details = app.el('findingList').children[0].children[0].children.find(child => child.tagName === 'details');
    const [, list, more] = details.children;
    details.open = true; details.handlers.toggle();
    assert.equal(list.children[1].textContent.length, 16384);
    assert.match(texts(list).join(' '), /Record preview truncated/);
    more.focus();
    while (!more.hidden) more.click();
    assert.equal(list.children.filter(child => child.tagName === 'pre').length, 100);
    assert.equal(doc.activeElement, list);
    assert.equal(list.className, 'finding-occurrences');
    assert.match(texts(details).join(' '), /Showing 100 of 110 occurrences/);
    assert.equal(JSON.stringify(report), original);
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
        assert.match(app.el('notice').textContent, /terminal completed or partial source scan ID/);
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
        scan_config: {source_scan_id: 'source', model_overrides: {asset: 'model'}, timeout_seconds: 180,
            evidence_profiles: {asset: 'fixture-v1'}, prompt_suite: 'protected-disclosure-v1', advanced_future_field: false}});
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
        if (path.startsWith('/api/schedules?')) return response({schedules: [], total: 0});
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

test('schedule creation requires explicit clean saved-template review and stays disabled', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        return response(path.includes('?') ? {schedules: [savedSchedule()], total: 1} : {schedule: savedSchedule({revision: 1})}, 201);
    });
    app.token = 'fixture-token';
    await app.createSchedule();
    assert.equal(calls.length, 0);
    app.showTemplate(savedTemplate());
    await app.createSchedule();
    assert.equal(calls.length, 0);
    reviewPin(app);
    app.el('templateEditor').value = '{unsaved';
    await app.createSchedule();
    assert.equal(calls.length, 0);
    reviewPin(app);
    await app.createSchedule();
    assert.equal(calls[0].path, '/api/schedules');
    assert.equal(calls[0].options.method, 'POST');
    assert.equal(calls[0].options.headers.Authorization, 'Bearer fixture-token');
    assert.deepEqual(JSON.parse(calls[0].options.body), {template_id: 'recipe', template_revision: 3, interval_seconds: 60, total_runs: 4});
    assert.equal(app.schedule.state, 'disabled');
    assert.equal(app.el('reviewScheduleTemplate').checked, false);
    assert.equal(app.el('enableScheduleBtn').disabled, true);
    assert.equal(app.scanId, null);
    assert.equal(app.timer, null);
    assert.equal(calls.length, 2);
});

test('schedule intervals and finite counts reject empty fractional or out-of-bound values', async () => {
    const {app} = fixture(async () => { throw new Error('Unexpected network call'); });
    app.token = 'fixture-token';
    for (const [interval, runs] of [['', '4'], ['59', '4'], ['2592001', '4'], ['60.5', '4'], ['60', ''],
        ['60', '0'], ['60', '101'], ['60', '1.5'], ['Infinity', '4']]) {
        reviewPin(app);
        app.el('scheduleInterval').value = interval; app.el('scheduleRuns').value = runs;
        await app.createSchedule();
        assert.match(app.el('notice').textContent, /integer interval/);
        assert.equal(app.scheduleBusy, false);
    }
});

test('loading refreshing and template editing cannot enable or silently rebind schedules', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        return response(path.includes('occurrences?') ? {occurrences: [], total: 0} :
            path.includes('?') ? {schedules: [savedSchedule()], total: 1} : {schedule: savedSchedule({state: 'paused', pause_reason: 'restart_review'})});
    });
    app.token = 'fixture-token'; reviewPin(app);
    await app.openSchedule('schedule');
    assert.equal(app.el('reviewScheduleTemplate').checked, false);
    assert.match(app.el('scheduleStatus').textContent, /restart_review/);
    await app.loadSchedules();
    await app.changeSchedule('enable');
    assert.ok(calls.every(call => !call.options.method));
    app.showTemplate(savedTemplate({revision: 4})); app.el('reviewScheduleTemplate').checked = true;
    await app.changeSchedule('enable');
    assert.equal(app.schedule.template_revision, 3);
    assert.match(app.el('notice').textContent, /exact pinned/);
    assert.equal(app.el('enableScheduleBtn').disabled, true);
});

test('enable and pause use displayed schedule revision and do not cancel admitted scans', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => {
        calls.push({path, options});
        return response(path.includes('?') ? {schedules: [], total: 0} : {schedule: savedSchedule({revision: JSON.parse(options.body).revision + 1,
            state: path.endsWith('/enable') ? 'enabled' : 'paused', pause_reason: path.endsWith('/pause') ? 'operator_paused' : null,
            outstanding_scan_id: 'admitted', admitted_runs: 1, next_due_at: path.endsWith('/enable') ? '2026-10-13T10:00:00+00:00' : null})});
    });
    app.token = 'fixture-token'; app.showSchedule(savedSchedule({id: 'schedule/id'})); reviewPin(app);
    // Return the exact requested ID in the controlled response.
    const fetcher = app.fetcher;
    app.fetcher = async (...args) => { const reply = await fetcher(...args); const json = await reply.json();
        if (json.schedule) json.schedule.id = 'schedule/id'; return response(json); };
    await app.changeSchedule('enable');
    assert.equal(calls[0].path, '/api/schedules/schedule%2Fid/enable');
    assert.deepEqual(JSON.parse(calls[0].options.body), {revision: 2});
    assert.equal(app.schedule.state, 'enabled');
    assert.equal(app.el('scheduleIdentity').focused, true);
    assert.match(app.el('scheduleTiming').textContent, /Next due \(UTC\): 2026/);
    assert.match(app.el('scheduleStatus').textContent, /1 of 4 admitted; 3 remaining.*admitted/);
    app.el('scheduleIdentity').focused = false;
    await app.changeSchedule('pause');
    assert.deepEqual(JSON.parse(calls[2].options.body), {revision: 3});
    assert.equal(app.schedule.state, 'paused');
    assert.equal(app.el('scheduleIdentity').focused, true);
    assert.equal(app.schedule.outstanding_scan_id, 'admitted');
    assert.ok(calls.every(call => !call.path.includes('/cancel')));
});

test('schedule conflicts retain displayed pin and recipe without retries', async () => {
    for (const action of ['create', 'enable', 'pause', 'delete']) {
        let calls = 0;
        const {app} = fixture(async () => { calls += 1; return response({error: 'stale'}, 409); });
        app.token = 'fixture-token'; reviewPin(app); app.showSchedule(savedSchedule());
        const editor = app.el('templateEditor').value;
        if (action === 'create') await app.createSchedule();
        else if (action === 'delete') await app.deleteSchedule();
        else await app.changeSchedule(action);
        assert.equal(calls, 1);
        assert.equal(app.schedule.revision, 2);
        assert.equal(app.schedule.template_revision, 3);
        assert.equal(app.el('templateEditor').value, editor);
        assert.match(app.el('notice').textContent, /Refresh detail.*no automatic retry/);
        assert.equal(app.scheduleBusy, false);
    }
});

test('missing foreign and policy schedule failures remain recoverable safe text', async () => {
    for (const status of [400, 403, 404, 429, 500, 503]) {
        const {app} = fixture(async () => response({error: '<script>policy</script>'}, status));
        app.token = 'fixture-token'; reviewPin(app); app.showSchedule(savedSchedule());
        await app.changeSchedule('enable');
        assert.equal(app.schedule.state, 'disabled');
        assert.equal(app.scheduleBusy, false);
        assert.equal(app.el('enableScheduleBtn').disabled, false);
        assert.match(app.el('notice').textContent, status === 404 ? /missing or unavailable/ : /<script>policy<\/script>/);
    }
});

test('schedule deletion is inactive-only and preserves independently admitted scans', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => { calls.push({path, options}); return response({schedules: [], total: 0}); });
    app.token = 'fixture-token'; app.scanId = 'existing';
    for (const changes of [{state: 'enabled'}, {outstanding_scan_id: 'outstanding'}]) {
        app.showSchedule(savedSchedule(changes)); await app.deleteSchedule();
        assert.equal(calls.length, 0);
        assert.equal(app.el('deleteScheduleBtn').disabled, true);
    }
    app.showSchedule(savedSchedule({state: 'completed', admitted_runs: 4}));
    assert.equal(app.el('enableScheduleBtn').disabled, true);
    await app.deleteSchedule();
    assert.equal(calls[0].options.method, 'DELETE');
    assert.equal(calls[0].path, '/api/schedules/schedule');
    assert.equal(app.scanId, 'existing');
    assert.equal(app.schedule, null);
    assert.equal(app.el('scheduleDetail').hidden, true);
    assert.equal(app.el('scheduleOccurrences').children.length, 0);
});

test('schedule and occurrence lists use bounded authenticated pages and literal text', async () => {
    const calls = [];
    const {app} = fixture(async (path, options) => { calls.push({path, options}); return response(path.includes('occurrences?') ?
        {occurrences: [occurrence(26, {scan_id: '<img>'})], total: 70} : {schedules: [savedSchedule({id: '<script>'})], total: 60}); });
    app.token = 'fixture-token'; app.scheduleOffset = 25;
    await app.loadSchedules();
    assert.equal(calls[0].path, '/api/schedules?limit=25&offset=25');
    assert.equal(calls[0].options.headers.Authorization, 'Bearer fixture-token');
    assert.match(app.el('scheduleList').children[0].textContent, /<script>/);
    app.showSchedule(savedSchedule()); app.occurrenceOffset = 25;
    await app.loadOccurrences();
    assert.equal(calls[1].path, '/api/schedules/schedule/occurrences?limit=25&offset=25');
    assert.match(app.el('scheduleOccurrences').children[0].textContent, /#26.*UTC.*<img>/);
    assert.equal(app.el('nextOccurrencesBtn').disabled, false);
    app.el('scheduleOccurrences').value = '<img>';
    app.selectScan = async id => { app.scanId = id; };
    await app.openOccurrence();
    assert.equal(app.scanId, '<img>');
    app.scheduleOffset = 100000; await app.loadSchedules();
    assert.equal(app.el('nextSchedulesBtn').disabled, true);
    app.el('nextSchedulesBtn').handlers.click(); assert.equal(app.scheduleOffset, 100000);
    app.occurrenceOffset = 75; app.el('nextOccurrencesBtn').handlers.click(); assert.equal(app.occurrenceOffset, 75);
});

test('schedule pages reject malformed rows and oversized lists before replacing valid display', async () => {
    for (const data of [{schedules: Array.from({length: 26}, () => savedSchedule()), total: 26},
        {schedules: [savedSchedule()], total: -1}, {schedules: [savedSchedule({admitted_runs: 5})], total: 1},
        {schedules: [savedSchedule({template_revision: 0})], total: 1}, {schedules: [savedSchedule({state: 'unknown'})], total: 1},
        {schedules: [savedSchedule({next_due_at: '2026-10-13T10:00:00'})], total: 1}]) {
        const {app} = fixture(async () => response(data)); app.token = 'fixture-token';
        app.append(app.el('scheduleList'), 'option', 'Previous valid page').value = 'previous';
        await app.loadSchedules();
        assert.equal(app.el('scheduleList').children[0].value, 'previous');
        assert.match(app.el('notice').textContent, /invalid schedule/);
    }
});

test('occurrence pages reject invalid totals ordinals UTC and oversized records without replacement', async () => {
    for (const data of [{occurrences: Array.from({length: 26}, (_, index) => occurrence(index + 1)), total: 26},
        {occurrences: [], total: 101}, {occurrences: [occurrence(0)], total: 1},
        {occurrences: [occurrence(2), occurrence(1)], total: 2}, {occurrences: [occurrence(1, {scan_id: ''})], total: 1},
        {occurrences: [occurrence(1, {created_at: 'invalid'})], total: 1},
        {occurrences: [occurrence(1, {created_at: '2026-10-13T10:00:00'})], total: 1}]) {
        const {app} = fixture(async () => response(data)); app.token = 'fixture-token'; app.showSchedule(savedSchedule());
        app.append(app.el('scheduleOccurrences'), 'option', 'Previous valid page').value = 'previous';
        await app.loadOccurrences();
        assert.equal(app.el('scheduleOccurrences').children[0].value, 'previous');
        assert.match(app.el('notice').textContent, /invalid.*occurrence/);
        assert.equal(app.el('refreshOccurrencesBtn').disabled, false);
    }
});

test('new schedule and occurrence page requests supersede stale success and failure responses', async () => {
    for (const target of ['schedule', 'occurrence']) for (const failure of [false, true]) {
        const replies = [];
        const {app} = fixture(() => new Promise(done => replies.push(done)));
        app.token = 'fixture-token'; app.showSchedule(savedSchedule());
        const load = () => target === 'schedule' ? app.loadSchedules() : app.loadOccurrences();
        const old = load();
        if (target === 'schedule') app.scheduleOffset = 25; else app.occurrenceOffset = 25;
        const recent = load();
        replies[1](response(target === 'schedule' ? {schedules: [savedSchedule({id: 'new'})], total: 26} : {occurrences: [occurrence(26)], total: 26}));
        await recent;
        replies[0](response(failure ? {error: 'Old failure'} : target === 'schedule' ? {schedules: [savedSchedule({id: 'old'})], total: 1} : {occurrences: [occurrence()], total: 1}, failure ? 500 : 200));
        await old;
        assert.equal(app.el(target === 'schedule' ? 'scheduleList' : 'scheduleOccurrences').children[0].value, target === 'schedule' ? 'new' : 'scan-26');
        assert.doesNotMatch(app.el('notice').textContent, /Old failure/);
    }
});

test('all schedule requests and late errors are suppressed after logout', async () => {
    for (const action of ['loadSchedules', 'openSchedule', 'createSchedule', 'changeSchedule', 'deleteSchedule', 'loadOccurrences']) {
        for (const failure of [false, true]) {
            let resolve;
            const {app} = fixture(() => new Promise(done => { resolve = done; }));
            app.token = 'fixture-token'; app.showSchedule(savedSchedule()); reviewPin(app);
            const pending = app[action](action === 'changeSchedule' ? 'enable' : 'schedule');
            app.logout();
            resolve(response(failure ? {error: 'Old failure'} : {schedule: savedSchedule(), schedules: [savedSchedule()], occurrences: [occurrence()], total: 1}, failure ? 500 : 200));
            await pending;
            assert.equal(app.el('notice').textContent, 'Signed out.');
            assert.equal(app.schedule, null);
            assert.equal(app.scheduleBusy, false);
            assert.equal(app.el('scheduleList').children.length, 0);
            assert.equal(app.el('scheduleOccurrences').children.length, 0);
            assert.equal(app.el('scheduleDetail').hidden, true);
            assert.equal(app.el('scheduleControls').disabled, true);
            assert.equal(app.el('reviewScheduleTemplate').checked, false);
        }
    }
});

test('pending schedule mutation blocks duplicates without locking template or scan namespace', async () => {
    let resolve; let calls = 0;
    const {app} = fixture(() => { calls += 1; return new Promise(done => { resolve = done; }); });
    app.token = 'fixture-token'; app.showSchedule(savedSchedule()); reviewPin(app);
    const pending = app.changeSchedule('enable');
    await app.changeSchedule('enable'); await app.deleteSchedule(); await app.openSchedule('another');
    assert.equal(calls, 1);
    assert.equal(app.templateBusy, false);
    assert.equal(app.el('updateTemplateBtn').disabled, false);
    app.selection += 1; app.scanId = 'newer';
    resolve(response({error: 'rejected'}, 403)); await pending;
    assert.equal(app.scanId, 'newer');
    assert.equal(app.scheduleBusy, false);
    assert.equal(app.el('enableScheduleBtn').disabled, false);
});

test('occurrence requests cannot populate or emit errors for a newly opened schedule', async () => {
    for (const failure of [false, true]) {
        let resolve;
        const {app} = fixture((path) => path.includes('/new') ? response(path.includes('occurrences') ? {occurrences: [], total: 0} :
            {schedule: savedSchedule({id: 'new'})}) : new Promise(done => { resolve = done; }));
        app.token = 'fixture-token'; app.showSchedule(savedSchedule());
        const old = app.loadOccurrences();
        await app.openSchedule('new');
        resolve(response(failure ? {error: 'Old occurrence failure'} : {occurrences: [occurrence()], total: 1}, failure ? 500 : 200));
        await old;
        assert.equal(app.schedule.id, 'new');
        assert.equal(app.el('scheduleOccurrences').children[0].value, '');
        assert.doesNotMatch(app.el('notice').textContent, /Old occurrence/);
        assert.equal(app.occurrenceBusy, false);
    }
});

test('review confirmation resets on editor input template changes deletion and discard', async () => {
    const {app} = fixture(async () => response({templates: [], total: 0}));
    app.token = 'fixture-token'; reviewPin(app);
    app.el('templateEditor').handlers.input(); assert.equal(app.el('reviewScheduleTemplate').checked, false);
    reviewPin(app); app.showTemplate(savedTemplate({revision: 4})); assert.equal(app.el('reviewScheduleTemplate').checked, false);
    reviewPin(app); app.el('discardTemplateBtn').handlers.click(); assert.equal(app.el('reviewScheduleTemplate').checked, false);
    reviewPin(app); await app.deleteTemplate(); assert.equal(app.el('reviewScheduleTemplate').checked, false);
    assert.equal(app.el('createScheduleBtn').disabled, true);
});

test('initial schedule list failure leaves authenticated refresh and manual flows usable', async () => {
    let fail = true;
    const {app} = fixture(async path => path === '/api/auth/token' ? response({token: 'fixture-token'}) :
        path.startsWith('/api/schedules?') ? fail ? response({error: 'Schedule service unavailable'}, 503) : response({schedules: [savedSchedule()], total: 1}) :
        path.startsWith('/api/templates?') ? response({templates: [], total: 0}) : response({scans: [], total: 0}));
    app.el('operatorKey').value = 'secret'; await app.login(event);
    assert.match(app.el('notice').textContent, /Schedule service unavailable/);
    assert.equal(app.el('refreshSchedulesBtn').disabled, false);
    assert.equal(app.el('saveTemplateBtn').disabled, false);
    fail = false; await app.loadSchedules();
    assert.equal(app.el('scheduleList').children[0].value, 'schedule');
});

test('401 schedule response clears all protected workflow state', async () => {
    const {app} = fixture(async () => response({error: 'expired'}, 401));
    app.token = 'fixture-token'; app.showSchedule(savedSchedule()); reviewPin(app);
    await app.changeSchedule('enable');
    assert.equal(app.token, null);
    assert.equal(app.schedule, null);
    assert.equal(app.template, null);
    assert.equal(app.el('scheduleDetail').hidden, true);
    assert.equal(app.el('scheduleControls').disabled, true);
});

test('unexpected server schedule IDs pins and active creation never become actionable', async () => {
    for (const changes of [{state: 'enabled'}, {template_revision: 4}, {template_id: 'different'}, {interval_seconds: 120},
        {total_runs: 5}, {admitted_runs: 1}, {outstanding_scan_id: 'unexpected'}, {next_due_at: '2026-10-13T10:00:00+00:00'},
        {revision: 2}, {pause_reason: 'policy_review'}]) {
        const {app} = fixture(async () => response({schedule: savedSchedule({revision: 1, ...changes})}));
        app.token = 'fixture-token'; reviewPin(app);
        await app.createSchedule();
        assert.equal(app.schedule, null);
        assert.match(app.el('notice').textContent, /unexpected schedule/);
    }
    const {app} = fixture(async () => response({schedule: savedSchedule({id: 'different'})}));
    app.token = 'fixture-token';
    await app.openSchedule('schedule');
    assert.equal(app.schedule, null);
    assert.match(app.el('notice').textContent, /different schedule/);
});

test('schedule transition responses cannot falsely claim enable pause or changed recurrence', async () => {
    for (const action of ['enable', 'pause']) for (const changes of [{state: 'disabled'}, {state: 'enabled'}, {state: 'paused'},
        {interval_seconds: 120}, {total_runs: 5}, {revision: 2}, {template_id: 'different'}, {template_revision: 4}, {id: 'different'}]) {
        if ((action === 'enable' && changes.state === 'enabled') || (action === 'pause' && changes.state === 'paused')) continue;
        const {app} = fixture(async () => response({schedule: savedSchedule({revision: 3, state: action === 'enable' ? 'enabled' : 'paused', ...changes})}));
        app.token = 'fixture-token'; app.showSchedule(savedSchedule()); reviewPin(app);
        await app.changeSchedule(action);
        assert.equal(app.schedule.state, 'disabled');
        assert.equal(app.schedule.revision, 2);
        assert.match(app.el('notice').textContent, /different schedule or pin|requested schedule transition/);
    }
});

test('schedule and template deletion move focus only after restoring enabled controls', async () => {
    for (const kind of ['Schedule', 'Template']) {
        const {app} = fixture(async () => response({templates: [], schedules: [], total: 0}));
        app.token = 'fixture-token'; app.showTemplate(savedTemplate()); app.showSchedule(savedSchedule());
        await app[`delete${kind}`]();
        const id = kind === 'Schedule' ? 'refreshSchedulesBtn' : 'refreshTemplatesBtn';
        assert.equal(app.el(id).disabled, false);
        assert.equal(app.el(id).focused, true);
    }
});

test('opening schedule detail focuses identity but background list or occurrences do not steal focus', async () => {
    const {app} = fixture(async path => response(path.includes('occurrences') ? {occurrences: [], total: 0} :
        path.includes('?') ? {schedules: [savedSchedule()], total: 1} : {schedule: savedSchedule()}));
    app.token = 'fixture-token';
    await app.openSchedule('schedule');
    assert.equal(app.el('scheduleIdentity').focused, true);
    app.el('scheduleIdentity').focused = false;
    await app.loadSchedules(); await app.loadOccurrences();
    assert.equal(app.el('scheduleIdentity').focused, false);
    app.logout();
    assert.equal(app.el('operatorKey').focused, true);
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

test('partial confirmed evidence retains risk with an explicit coverage warning', () => {
    const {app} = fixture();
    const check = {rule_id: 'prompt_injection.system_prompt_extraction', probe_id: 'sample', probe_version: 'v2',
        status: 'failed', outcome: 'confirmed', responses_evaluated: 1, requests_attempted: 2};
    const report = checkedReport([check], 70);
    report.status = 'partial';
    report.risk_assessment_status = 'partial';
    report.agents[0].security_status = 'partial';
    report.agents[0].vulnerabilities = [{...check, evidence_status: 'confirmed', severity: 'high'}];
    report.source_inventory = {coverage_complete: false};
    app.renderReport(report);
    assert.equal(app.el('riskScore').textContent, '70.0 / 100 (partial coverage)');
    assert.ok(texts(app.el('assetList')).includes('Risk: 70.0 / 100 (partial coverage)'));
    assert.match(app.el('reportNote').textContent, /Source inventory coverage is incomplete/);
});

test('stale prompt nondisclosure passes cannot display a zero risk verdict', () => {
    const {app} = fixture();
    for (const rule of ['prompt_injection.system_prompt_extraction', 'tenant_isolation_violation']) {
        app.renderReport(checkedReport([{rule_id: rule, status: 'completed', outcome: 'passed',
            responses_evaluated: 5, requests_attempted: 5}], 0));
        assert.equal(app.el('riskScore').textContent, 'Not assessed');
    }
});

test('a confirmed check without matching versioned finding cannot display risk', () => {
    const {app} = fixture();
    app.renderReport(checkedReport([{rule_id: 'prompt_injection.system_prompt_extraction', probe_id: 'sample',
        probe_version: 'v2', status: 'completed', outcome: 'confirmed', responses_evaluated: 1, requests_attempted: 1}], 70));
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
});

test('old scoring policies and skipped assets cannot display a current risk verdict', () => {
    const {app} = fixture();
    const check = {rule_id: 'prompt_injection.system_prompt_extraction', probe_id: 'sample', probe_version: 'v2',
        status: 'completed', outcome: 'confirmed', responses_evaluated: 1, requests_attempted: 1};
    const report = checkedReport([check], 6.58);
    report.agents[0].vulnerabilities = [{...check, evidence_status: 'confirmed', severity: 'high'}];
    delete report.agents[0].risk_scoring_policy;
    app.renderReport(report);
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
    report.agents[0].risk_scoring_policy = 'severity-floor-v2';
    report.agents[0].security_status = 'skipped';
    report.agents[0].risk_score = report.summary.overall_risk_score = 70;
    app.renderReport(report);
    assert.equal(app.el('riskScore').textContent, 'Not assessed');
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

test('final check page restores focus only when its disappearing button owns focus', () => {
    for (const count of [18, 36, 110]) {
        for (const focused of [false, true]) {
            const {app, doc} = fixture();
            const card = new Element();
            app.el('openScanId').focus();
            app.renderChecks(card, Array.from({length: count}, () => ({rule_id: '<fixture>'})), 'Check records for <fixture>');
            const [details] = card.children;
            const [, list, more] = details.children;
            assert.equal(list.attributes.role, 'region');
            assert.equal(list.attributes['aria-label'], 'Check records for <fixture>');
            assert.equal(doc.activeElement, app.el('openScanId'));
            for (let page = 0; page < 6 && !more.hidden; page += 1) {
                if (focused) more.focus();
                more.click();
            }
            assert.equal(more.hidden, true);
            assert.equal(list.children.length, Math.min(count, 100));
            assert.equal(doc.activeElement, focused && count > 18 ? list : app.el('openScanId'));
        }
    }
});

test('dashboard associates scope and model guidance and names persistent audit and status regions', () => {
    const html = fs.readFileSync(require.resolve('../templates/dashboard.html'), 'utf8');
    const descriptions = {scanType: 'modelProbeHelp', networkRanges: 'scopeHelp networkHelp', repositories: 'scopeHelp pathHelp',
        trafficSources: 'scopeHelp pathHelp', sourceScanId: 'sourceHelp modelProbeHelp', modelOverrides: 'modelSelectionHelp modelProbeHelp'};
    for (const [id, describedby] of Object.entries(descriptions)) {
        assert.match(html, new RegExp(`id="${id}"[^>]*aria-describedby="${describedby}"`));
        for (const hint of describedby.split(' ')) assert.equal((html.match(new RegExp(`id="${hint}"`, 'g')) || []).length, 1);
    }
    assert.match(html, /id="auditRegion"[^>]*tabindex="0"[^>]*role="region"[^>]*aria-labelledby="auditTitle"/);
    assert.match(html, /id="scanAnnouncement"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
});

test('enabled control border contrast exceeds three to one against adjacent white', () => {
    const css = fs.readFileSync(require.resolve('../static/css/dashboard.css'), 'utf8');
    assert.match(css, /input,textarea,select\{[^}]*border:1px solid #6e7d8b/);
    assert.match(css, /\.secondary\{[^}]*border-color:#6e7d8b/);
    const channels = [0x6e, 0x7d, 0x8b].map(channel => channel / 255).map(channel =>
        channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
    const luminance = channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
    assert.ok(1.05 / (luminance + 0.05) >= 3);
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
