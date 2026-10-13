class AIAgentScanner {
    constructor() {
        this.token = null;
        this.currentScanId = null;
        this.pollInterval = null;
        document.getElementById('loginForm').addEventListener('submit', e => this.login(e));
        document.getElementById('logoutBtn').addEventListener('click', () => this.logout());
        document.getElementById('scanForm').addEventListener('submit', e => this.startScan(e));
        document.getElementById('startScanBtn').disabled = true;
    }

    status(message) {
        document.getElementById('authStatus').textContent = message;
    }

    logout() {
        this.token = null;
        this.currentScanId = null;
        clearInterval(this.pollInterval);
        document.getElementById('startScanBtn').disabled = true;
        document.getElementById('recent-scans').textContent = '';
        for (const id of ['agents-count', 'vulns-count', 'risk-score', 'last-scan']) {
            document.getElementById(id).textContent = '-';
        }
        this.status('Signed out.');
    }

    async login(event) {
        event.preventDefault();
        this.logout();
        const input = document.getElementById('operatorKey');
        const apiKey = input.value;
        input.value = '';
        try {
            const response = await fetch('/api/auth/token', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({api_key: apiKey}),
                cache: 'no-store'
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Sign in failed');
            this.token = data.token;
            document.getElementById('startScanBtn').disabled = false;
            this.status('Signed in. Reloading this page signs you out.');
            await this.loadAgents();
        } catch (error) {
            this.status(error.message);
        }
    }

    async api(path, options = {}) {
        if (!this.token) throw new Error('Sign in first.');
        const response = await fetch(path, {
            ...options,
            headers: {...options.headers, Authorization: `Bearer ${this.token}`}
        });
        if (response.status === 401) {
            this.logout();
            throw new Error('Session expired. Sign in again.');
        }
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Request failed');
        return data;
    }

    async startScan(event) {
        event.preventDefault();
        const targets = document.getElementById('networkRanges').value.split('\n')
            .map(line => line.trim()).filter(Boolean);
        if (!targets.length) return this.status('Enter a scan target.');
        try {
            const data = await this.api('/api/scans', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    scan_name: document.getElementById('scanName').value || 'Network Scan',
                    scan_type: document.getElementById('scanType').value,
                    target_scope: {
                        include_network: true,
                        network_ranges: targets.filter(target => target.includes('/') || /^[0-9.]+$/.test(target)),
                        domains: targets.filter(target => !target.includes('/') && !/^[0-9.]+$/.test(target))
                    }
                })
            });
            this.currentScanId = data.scan_id;
            clearInterval(this.pollInterval);
            this.pollInterval = setInterval(() => this.poll(), 5000);
            this.status('Scan started.');
        } catch (error) {
            this.status(error.message);
        }
    }

    async poll() {
        if (!this.currentScanId) return;
        try {
            const data = await this.api(`/api/scans/${this.currentScanId}/status`);
            document.getElementById('recent-scans').textContent =
                `${data.scan_id}: ${data.status} (${data.progress}%)`;
            if (['completed', 'failed'].includes(data.status)) {
                clearInterval(this.pollInterval);
                document.getElementById('last-scan').textContent = data.status;
                await this.loadAgents();
            }
        } catch (error) {
            clearInterval(this.pollInterval);
            this.status(error.message);
        }
    }

    async loadAgents() {
        const data = await this.api('/api/agents');
        document.getElementById('agents-count').textContent = data.agents.length;
    }
}

new AIAgentScanner();
