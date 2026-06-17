document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const queryInput = document.getElementById('query-input');
    const runBtn = document.getElementById('run-btn');
    const presetBtns = document.querySelectorAll('.preset-btn');
    const refreshLogsBtn = document.getElementById('refresh-logs-btn');
    const logsTableBody = document.querySelector('#logs-table tbody');
    const consoleBox = document.getElementById('console-box');
    const reportBox = document.getElementById('report-box');

    let isRunning = false;

    // Load logs on startup
    fetchLogs();

    // Event Listeners
    runBtn.addEventListener('click', runAnalysis);
    queryInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') runAnalysis();
    });
    
    refreshLogsBtn.addEventListener('click', fetchLogs);

    presetBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            if (isRunning) return;
            const queryText = btn.getAttribute('data-query');
            queryInput.value = queryText;
            runAnalysis();
        });
    });

    // Fetch SIEM logs from API
    async function fetchLogs() {
        try {
            logsTableBody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: #777;">Loading logs...</td></tr>';
            const response = await fetch('/api/logs');
            const data = await response.json();
            
            if (response.ok) {
                renderLogs(data);
            } else {
                logsTableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: red;">Error loading logs: ${data.error}</td></tr>`;
            }
        } catch (err) {
            logsTableBody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: red;">Connection refused. Verify that the FastAPI backend server is running.</td></tr>`;
        }
    }

    function renderLogs(logs) {
        if (!logs || logs.length === 0) {
            logsTableBody.innerHTML = '<tr><td colspan="9" style="text-align: center;">No logs available in database.</td></tr>';
            return;
        }
        
        logsTableBody.innerHTML = logs.map(log => {
            const statusClass = log.status === 'success' ? 'text-green' : 'text-red';
            return `
                <tr>
                    <td><code>${formatTimestamp(log.timestamp)}</code></td>
                    <td><code>${log.event_id}</code></td>
                    <td><strong>${log.user}</strong></td>
                    <td><code>${log.source_ip}</code></td>
                    <td>${log.country}</td>
                    <td><code>${log.action}</code></td>
                    <td><span class="${statusClass}">${log.status.toUpperCase()}</span></td>
                    <td><code>${log.resource}</code></td>
                    <td>${log.additional_info}</td>
                </tr>
            `;
        }).join('');
    }

    function formatTimestamp(isoStr) {
        const d = new Date(isoStr);
        return d.toLocaleTimeString();
    }

    // Run Triage Pipeline
    async function runAnalysis() {
        const query = queryInput.value.trim();
        if (!query || isRunning) return;

        // Reset UI states
        isRunning = true;
        runBtn.disabled = true;
        runBtn.textContent = 'Processing...';
        
        consoleBox.textContent = '[SYSTEM] Initializing multi-agent triage...\n';
        reportBox.innerHTML = '<p style="color: #777; font-style: italic;">Pipeline execution in progress. Compiling security report...</p>';

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query: query })
            });
            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Execution failed.');
            }

            // Animate trace logs with simple delays
            await animateLogs(result.trace, result);

        } catch (err) {
            consoleBox.textContent += `\n[ERROR] Pipeline execution failed: ${err.message}\n`;
            reportBox.innerHTML = `<p style="color: red;">Analysis failed: ${err.message}</p>`;
        } finally {
            isRunning = false;
            runBtn.disabled = false;
            runBtn.textContent = 'Run Pipeline';
        }
    }

    // Sequentially print logs to preformatted box
    async function animateLogs(trace, finalResult) {
        const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        consoleBox.textContent = ''; // clear

        for (let i = 0; i < trace.length; i++) {
            const step = trace[i];
            const timestamp = new Date().toLocaleTimeString();
            
            let logLine = `[${timestamp}] [${step.agent}] ${step.message}\n`;
            
            if (step.agent === 'LOG_RETRIEVER' && step.status === 'completed' && step.output) {
                logLine += `>> Extracted raw logs:\n`;
                step.output.forEach(l => {
                    logLine += `   - ID:${l.event_id} | User:${l.user} | Resource:${l.resource} | Country:${l.country}\n`;
                });
            }
            
            consoleBox.textContent += logLine;
            consoleBox.scrollTop = consoleBox.scrollHeight;
            
            await delay(600); // short delay to show processing flow
        }

        // Show final report
        renderReport(finalResult.threat_score, finalResult.trace[finalResult.trace.length - 1].output.final_report);
    }

    // Parse minimal markdown for report formatting
    function renderReport(riskLevel, markdownText) {
        let riskColor = 'gray';
        if (riskLevel === 'HIGH') riskColor = 'red';
        if (riskLevel === 'MEDIUM') riskColor = 'orange';
        if (riskLevel === 'LOW') riskColor = 'green';

        let html = `<div><strong>TRIAGE VERDICT: <span style="color: ${riskColor}; font-weight: bold;">${riskLevel} RISK</span></strong></div><hr>`;
        
        let mdHtml = markdownText
            .replace(/^#### (.*?)$/gm, '<h4>$1</h4>')
            .replace(/^### (.*?)$/gm, '<h3>$1</h3>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/`(.*?)`/g, '<code>$1</code>')
            .replace(/^- (.*?)$/gm, '<li>$1</li>')
            .replace(/^\d+\. (.*?)$/gm, '<li>$1</li>')
            .replace(/\n\n/g, '</p><p>');

        mdHtml = mdHtml.replace(/(<li>.*?<\/li>)/gs, '<ul>$1</ul>');
        html += `<div class="md-body"><p>${mdHtml}</p></div>`;
        
        // Cleanup empty tags
        html = html.replace(/<p><h/g, '<h').replace(/<\/h4><\/p>/g, '</h4>').replace(/<\/h3><\/p>/g, '</h3>');
        
        reportBox.innerHTML = html;
    }
});
