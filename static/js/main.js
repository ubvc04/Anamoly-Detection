/**
 * Network Anomaly Detector - Advanced Dynamic UI
 * Provides comprehensive real-time functionality for network monitoring
 */

class NetworkAnomalyDetector {
    constructor() {
        this.updateInterval = 3000; // 3 seconds for real-time feel
        this.charts = {};
        this.isCapturing = false;
        this.isDetecting = false;
        this.interfaces = [];
        this.statistics = {};
        
        this.init();
    }

    init() {
        console.log('Initializing Network Anomaly Detector UI...');
        
        // Initialize components
        this.initializeBootstrapComponents();
        this.bindEventHandlers();
        this.loadInitialData();
        this.startRealTimeUpdates();
        
        console.log('UI initialized successfully');
    }

    initializeBootstrapComponents() {
        // Initialize tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
        
        // Initialize popovers
        const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        popoverTriggerList.map(popoverTriggerEl => new bootstrap.Popover(popoverTriggerEl));
        
        // Initialize modals
        const modalList = [].slice.call(document.querySelectorAll('.modal'));
        modalList.map(modalEl => new bootstrap.Modal(modalEl));
    }

    bindEventHandlers() {
        // Packet Capture Controls
        const startCaptureBtn = document.getElementById('start-capture-btn');
        const stopCaptureBtn = document.getElementById('stop-capture-btn');
        
        if (startCaptureBtn) {
            startCaptureBtn.addEventListener('click', () => this.startCapture());
        }
        if (stopCaptureBtn) {
            stopCaptureBtn.addEventListener('click', () => this.stopCapture());
        }

        // Detection Controls
        const startDetectionBtn = document.getElementById('start-detection-btn');
        const stopDetectionBtn = document.getElementById('stop-detection-btn');
        const retrainBtn = document.getElementById('retrain-model-btn');
        
        if (startDetectionBtn) {
            startDetectionBtn.addEventListener('click', () => this.startDetection());
        }
        if (stopDetectionBtn) {
            stopDetectionBtn.addEventListener('click', () => this.stopDetection());
        }
        if (retrainBtn) {
            retrainBtn.addEventListener('click', () => this.retrainModel());
        }

        // Interface selection
        const interfaceCheckboxes = document.querySelectorAll('input[name="interfaces"]');
        interfaceCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updateInterfaceSelection());
        });

        // Settings form
        const settingsForm = document.getElementById('settings-form');
        if (settingsForm) {
            settingsForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.updateSettings();
            });
        }

        // False positive buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('mark-false-positive')) {
                const alertId = e.target.dataset.alertId;
                this.markFalsePositive(alertId);
            }
        });
    }

    async loadInitialData() {
        try {
            await Promise.all([
                this.updateStatistics(),
                this.loadInterfaces(),
                this.updateSystemStatus()
            ]);
        } catch (error) {
            console.error('Error loading initial data:', error);
            this.showAlert('Error loading initial data', 'warning');
        }
    }

    startRealTimeUpdates() {
        // Main update loop
        this.updateTimer = setInterval(() => {
            this.updateStatistics();
            this.updateSystemStatus();
            this.updateCharts();
        }, this.updateInterval);

        // Faster updates for critical metrics
        this.fastUpdateTimer = setInterval(() => {
            this.updateRealTimeMetrics();
        }, 1000);
    }

    async updateStatistics() {
        try {
            const response = await fetch('/api/statistics');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            this.statistics = await response.json();
            this.updateStatisticsDisplay();
            
        } catch (error) {
            console.error('Error fetching statistics:', error);
        }
    }

    updateStatisticsDisplay() {
        const stats = this.statistics;
        
        // Packet capture statistics
        if (stats.capture) {
            this.updateElement('packets-captured', this.formatNumber(stats.capture.packets_captured || 0));
            this.updateElement('packet-rate', `${(stats.capture.packets_per_second || 0).toFixed(1)} packets/sec`);
            this.updateElement('bytes-captured', this.formatBytes(stats.capture.bytes_captured || 0));
            this.updateElement('flows-analyzed', this.formatNumber(stats.capture.flows_completed || 0));
            this.updateElement('active-flows', this.formatNumber(stats.capture.active_flows || 0));
            this.updateElement('queue-size', stats.capture.queue_size || 0);
        }

        // Detection statistics
        if (stats.detection) {
            this.updateElement('anomalies-detected', this.formatNumber(stats.detection.anomalies || 0));
            this.updateElement('alerts-generated', this.formatNumber(stats.detection.alerts || 0));
            this.updateElement('false-positives', this.formatNumber(stats.detection.false_positives || 0));
        }

        // System metrics
        if (stats.system) {
            this.updateElement('cpu-usage', `${(stats.system.cpu_percent || 0).toFixed(1)}%`);
            this.updateElement('memory-usage', `${(stats.system.memory_percent || 0).toFixed(1)}%`);
            this.updateProgressBar('cpu-progress', stats.system.cpu_percent || 0);
            this.updateProgressBar('memory-progress', stats.system.memory_percent || 0);
        }

        // Model information
        if (stats.model) {
            this.updateElement('model-status', stats.model.status || 'Unknown');
            this.updateElement('model-accuracy', stats.model.accuracy ? `${(stats.model.accuracy * 100).toFixed(1)}%` : 'N/A');
            this.updateElement('model-trained', stats.model.last_trained || 'Never');
            
            const statusBadge = document.getElementById('model-status-badge');
            if (statusBadge) {
                statusBadge.className = `badge ${stats.model.status === 'loaded' ? 'bg-success' : 'bg-warning'}`;
                statusBadge.textContent = stats.model.status || 'Unknown';
            }
        }
    }

    async updateSystemStatus() {
        try {
            const response = await fetch('/api/statistics');
            if (!response.ok) return;
            
            const data = await response.json();
            
            // Update capture status
            this.isCapturing = data.capture?.running || false;
            this.updateCaptureControls();
            
            // Update detection status
            this.isDetecting = data.detection?.running || false;
            this.updateDetectionControls();
            
            // Update system status indicator
            this.updateSystemStatusIndicator(data);
            
        } catch (error) {
            console.error('Error updating system status:', error);
        }
    }

    updateSystemStatusIndicator(data) {
        const statusElement = document.getElementById('system-status');
        const statusText = document.getElementById('system-status-text');
        
        if (!statusElement) return;
        
        let status = 'warning';
        let message = 'Some systems offline';
        
        if (this.isCapturing && this.isDetecting) {
            status = 'success';
            message = 'All systems operational';
        } else if (this.isCapturing || this.isDetecting) {
            status = 'warning';
            message = 'Partial operation';
        } else {
            status = 'danger';
            message = 'Systems offline';
        }
        
        statusElement.className = `badge bg-${status}`;
        if (statusText) statusText.textContent = message;
    }

    updateCaptureControls() {
        const startBtn = document.getElementById('start-capture-btn');
        const stopBtn = document.getElementById('stop-capture-btn');
        const statusBadge = document.getElementById('capture-status');
        
        if (startBtn && stopBtn) {
            if (this.isCapturing) {
                startBtn.style.display = 'none';
                stopBtn.style.display = 'inline-block';
                if (statusBadge) {
                    statusBadge.className = 'badge bg-success';
                    statusBadge.textContent = 'Running';
                }
            } else {
                startBtn.style.display = 'inline-block';
                stopBtn.style.display = 'none';
                if (statusBadge) {
                    statusBadge.className = 'badge bg-secondary';
                    statusBadge.textContent = 'Stopped';
                }
            }
        }
    }

    updateDetectionControls() {
        const startBtn = document.getElementById('start-detection-btn');
        const stopBtn = document.getElementById('stop-detection-btn');
        const statusBadge = document.getElementById('detection-status');
        
        if (startBtn && stopBtn) {
            if (this.isDetecting) {
                startBtn.style.display = 'none';
                stopBtn.style.display = 'inline-block';
                if (statusBadge) {
                    statusBadge.className = 'badge bg-success';
                    statusBadge.textContent = 'Running';
                }
            } else {
                startBtn.style.display = 'inline-block';
                stopBtn.style.display = 'none';
                if (statusBadge) {
                    statusBadge.className = 'badge bg-secondary';
                    statusBadge.textContent = 'Stopped';
                }
            }
        }
    }

    async loadInterfaces() {
        try {
            const response = await fetch('/api/statistics');
            if (!response.ok) return;
            
            const data = await response.json();
            if (data.system && data.system.available_interfaces) {
                this.interfaces = data.system.available_interfaces;
                this.updateInterfacesList();
            }
        } catch (error) {
            console.error('Error loading interfaces:', error);
        }
    }

    updateInterfacesList() {
        const container = document.getElementById('interfaces-list');
        if (!container) return;
        
        container.innerHTML = '';
        
        if (this.interfaces.length === 0) {
            container.innerHTML = '<p class="text-muted">No network interfaces available</p>';
            return;
        }
        
        this.interfaces.forEach(iface => {
            const div = document.createElement('div');
            div.className = 'form-check';
            div.innerHTML = `
                <input class="form-check-input" type="checkbox" value="${iface.name}" 
                       id="interface-${iface.name}" name="interfaces">
                <label class="form-check-label" for="interface-${iface.name}">
                    ${iface.name} - ${iface.description || 'No description'}
                </label>
            `;
            container.appendChild(div);
        });
    }

    async startCapture() {
        try {
            const selectedInterfaces = this.getSelectedInterfaces();
            
            if (selectedInterfaces.length === 0) {
                // If no interfaces selected, use all available or default
                this.showAlert('Using default network interface...', 'info');
            }

            this.showAlert('Starting packet capture...', 'info');
            
            const response = await fetch('/api/control/capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'start',
                    interfaces: selectedInterfaces.length > 0 ? selectedInterfaces : null
                })
            });

            const data = await response.json();
            
            if (response.ok && data.status === 'started') {
                this.showAlert('Packet capture started successfully', 'success');
                this.isCapturing = true;
                this.updateCaptureControls();
            } else {
                this.showAlert(`Failed to start capture: ${data.error || 'Unknown error'}`, 'danger');
            }
        } catch (error) {
            this.showAlert(`Error starting capture: ${error.message}`, 'danger');
        }
    }

    async stopCapture() {
        try {
            const response = await fetch('/api/control/capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'stop' })
            });

            const data = await response.json();
            
            if (response.ok && data.status === 'stopped') {
                this.showAlert('Packet capture stopped', 'info');
                this.isCapturing = false;
                this.updateCaptureControls();
            } else {
                this.showAlert(`Failed to stop capture: ${data.error || 'Unknown error'}`, 'danger');
            }
        } catch (error) {
            this.showAlert(`Error stopping capture: ${error.message}`, 'danger');
        }
    }

    async startDetection() {
        try {
            this.showAlert('Starting anomaly detection...', 'info');
            
            const response = await fetch('/api/control/detection', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'start' })
            });

            const data = await response.json();
            
            if (response.ok && data.status === 'started') {
                this.showAlert('Anomaly detection started successfully', 'success');
                this.isDetecting = true;
                this.updateDetectionControls();
            } else {
                this.showAlert(`Failed to start detection: ${data.error || 'Unknown error'}`, 'danger');
            }
        } catch (error) {
            this.showAlert(`Error starting detection: ${error.message}`, 'danger');
        }
    }

    async stopDetection() {
        try {
            const response = await fetch('/api/control/detection', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'stop' })
            });

            const data = await response.json();
            
            if (response.ok && data.status === 'stopped') {
                this.showAlert('Anomaly detection stopped', 'info');
                this.isDetecting = false;
                this.updateDetectionControls();
            } else {
                this.showAlert(`Failed to stop detection: ${data.error || 'Unknown error'}`, 'danger');
            }
        } catch (error) {
            this.showAlert(`Error stopping detection: ${error.message}`, 'danger');
        }
    }

    async retrainModel() {
        if (!confirm('Are you sure you want to retrain the ML model? This may take several minutes.')) {
            return;
        }
        
        try {
            this.showAlert('Starting model retraining...', 'info');
            
            const response = await fetch('/api/train-model', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ force_retrain: true })
            });

            const data = await response.json();
            
            if (response.ok && data.success) {
                this.showAlert('Model retraining completed successfully', 'success');
            } else {
                this.showAlert(`Model retraining failed: ${data.error || data.message || 'Unknown error'}`, 'danger');
            }
        } catch (error) {
            this.showAlert(`Error during model retraining: ${error.message}`, 'danger');
        }
    }

    async markFalsePositive(alertId) {
        try {
            const response = await fetch(`/api/alert/${alertId}/false-positive`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();
            
            if (response.ok && data.success) {
                this.showAlert('Alert marked as false positive', 'success');
                // Refresh the current page to update the alerts list
                setTimeout(() => location.reload(), 1000);
            } else {
                this.showAlert(`Failed to mark false positive: ${data.error || 'Unknown error'}`, 'danger');
            }
        } catch (error) {
            this.showAlert(`Error marking false positive: ${error.message}`, 'danger');
        }
    }

    getSelectedInterfaces() {
        const checkboxes = document.querySelectorAll('input[name="interfaces"]:checked');
        return Array.from(checkboxes).map(cb => cb.value);
    }

    updateInterfaceSelection() {
        const selected = this.getSelectedInterfaces();
        const startBtn = document.getElementById('start-capture-btn');
        
        if (startBtn) {
            startBtn.disabled = false; // Allow starting even with no selection (will use default)
        }
    }

    updateCharts() {
        // Update Plotly charts if they exist
        if (typeof Plotly !== 'undefined') {
            const chartElements = document.querySelectorAll('[id$="-chart"]');
            chartElements.forEach(element => {
                if (element.data) {
                    Plotly.redraw(element);
                }
            });
        }
    }

    updateRealTimeMetrics() {
        // Quick updates for time-sensitive metrics
        const currentTime = new Date().toLocaleTimeString();
        this.updateElement('last-update', currentTime);
        
        // Update any live counters or indicators
        this.updateLiveIndicators();
    }

    updateLiveIndicators() {
        // Add subtle animation to active status indicators
        const activeIndicators = document.querySelectorAll('.badge.bg-success');
        activeIndicators.forEach(indicator => {
            if (indicator.textContent === 'Running') {
                indicator.style.animation = 'pulse 2s infinite';
            }
        });
    }

    // Utility methods
    updateElement(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    }

    updateProgressBar(id, value) {
        const element = document.getElementById(id);
        if (element) {
            element.style.width = `${Math.min(100, Math.max(0, value))}%`;
            element.setAttribute('aria-valuenow', value);
        }
    }

    formatNumber(num) {
        if (num >= 1000000) {
            return (num / 1000000).toFixed(1) + 'M';
        } else if (num >= 1000) {
            return (num / 1000).toFixed(1) + 'K';
        }
        return num.toString();
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alert-container') || document.querySelector('main');
        
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            <i class="fas fa-${this.getAlertIcon(type)}"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        
        // Insert at the beginning
        alertContainer.insertBefore(alertDiv, alertContainer.firstChild);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    getAlertIcon(type) {
        const icons = {
            'success': 'check-circle',
            'danger': 'exclamation-triangle',
            'warning': 'exclamation-circle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    destroy() {
        // Clean up timers
        if (this.updateTimer) clearInterval(this.updateTimer);
        if (this.fastUpdateTimer) clearInterval(this.fastUpdateTimer);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing Network Anomaly Detector...');
    window.anomalyDetector = new NetworkAnomalyDetector();
});

// Global functions for backward compatibility
function startCapture() {
    if (window.anomalyDetector) {
        window.anomalyDetector.startCapture();
    }
}

function stopCapture() {
    if (window.anomalyDetector) {
        window.anomalyDetector.stopCapture();
    }
}

function startDetection() {
    if (window.anomalyDetector) {
        window.anomalyDetector.startDetection();
    }
}

function stopDetection() {
    if (window.anomalyDetector) {
        window.anomalyDetector.stopDetection();
    }
}

function retrainModel() {
    if (window.anomalyDetector) {
        window.anomalyDetector.retrainModel();
    }
}

function markFalsePositive(alertId) {
    if (window.anomalyDetector) {
        window.anomalyDetector.markFalsePositive(alertId);
    }
}
