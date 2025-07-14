class AIAgentScanner {
    constructor() {
        this.currentScanId = null;
        this.pollInterval = null;
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadDashboardData();
        this.loadRecentScans();
    }
    
    setupEventListeners() {
        const form = document.getElementById('scanForm');
        form.addEventListener('submit', (e) => this.handleScanSubmit(e));
    }
    
    async handleScanSubmit(e) {
        e.preventDefault();
        
        const scanName = document.getElementById('scanName').value || 'Network Scan';
        const scanType = document.getElementById('scanType').value;
        const networkRanges = document.getElementById('networkRanges').value
            .split('\n')
            .filter(line => line.trim())
            .map(line => line.trim());
        
        if (networkRanges.length === 0) {
            alert('Please enter at least one network range or domain');
            return;
        }
        
        try {
            const response = await fetch('/api/scans', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    scan_name: scanName,
                    scan_type: scanType,
                    target_scope: {
                        include_network: true,
                        network_ranges: networkRanges,
                        domains: networkRanges.filter(range => !range.includes('/'))
                    }
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.currentScanId = data.scan_id;
                this.startProgressPolling();
                alert('Scan started successfully!');
            } else {
                alert('Error: ' + data.error);
            }
        } catch (error) {
            alert('Network error: ' + error.message);
        }
    }
    
    startProgressPolling() {
        this.pollInterval = setInterval(async () => {
            if (!this.currentScanId) return;
            
            try {
                const response = await fetch(`/api/scans/${this.currentScanId}/status`);
                const data = await response.json();
                
                if (data.success) {
                    this.updateScanProgress(data);
                    
                    if (data.status === 'completed' || data.status === 'failed') {
                        clearInterval(this.pollInterval);
                        this.loadRecentScans();
                        this.loadDashboardData();
                    }
                }
            } catch (error) {
                console.error('Error polling scan status:', error);
            }
        }, 5000);
    }
    
    updateScanProgress(data) {
        // Update UI with scan progress
        console.log('Scan progress:', data);
    }
    
    async loadDashboardData() {
        try {
            // Load summary statistics
            const response = await fetch('/api/agents');
            const data = await response.json();
            
            if (data.success) {
                //
