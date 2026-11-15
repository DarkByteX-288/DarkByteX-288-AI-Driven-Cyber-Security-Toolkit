document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("network-scan-form");
    const submitButton = document.getElementById("start-scan-button");
    const cancelButton = document.getElementById("cancel-scan-button");
    const status = document.getElementById("scan-status");
    const progressBar = document.getElementById("scan-progress-bar");
    const progressLabel = document.getElementById("scan-progress-label");
    const progressTrack = progressBar.closest('[role="progressbar"]');
    const results = document.getElementById("scan-results");
    const historyBody = document.getElementById("scan-history");
    const reportLinks = document.getElementById("scan-report-links");
    const errorNode = document.getElementById("scan-error");
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    const csrfToken = csrfMeta ? csrfMeta.content : "";
    let activeScanId = null;
    let pollTimer = null;

    async function request(url, options = {}) {
        const headers = { "X-CSRFToken": csrfToken, ...(options.headers || {}) };
        const response = await fetch(url, { ...options, headers, credentials: "same-origin" });
        const contentType = response.headers.get("content-type") || "";
        const payload = contentType.includes("application/json") ? await response.json() : {};
        if (!response.ok) {
            throw new Error(payload.error || `Request failed (${response.status}).`);
        }
        return payload;
    }

    function addText(parent, tag, text, className) {
        const element = document.createElement(tag);
        element.textContent = text == null ? "" : String(text);
        if (className) element.className = className;
        parent.appendChild(element);
        return element;
    }

    function statusClass(value) {
        if (value === "completed" || value === "open") return "status-success";
        if (value === "failed") return "status-danger";
        if (value === "running" || value === "queued" || value === "filtered") return "status-warning";
        return "status-neutral";
    }

    function renderFindings(scan) {
        results.replaceChildren();
        const hosts = scan.hosts || [];
        addText(results, "h3", `Observed hosts (${hosts.length})`, "h6 mb-3");
        if (!hosts.length) {
            addText(results, "p", "Nmap returned no host records for this scan.", "data-note");
        }
        hosts.forEach((host) => {
            const section = document.createElement("section");
            section.className = "scan-host-card";
            const heading = addText(
                section,
                "h4",
                `${host.address}${host.hostname ? ` · ${host.hostname}` : ""}`,
                "h6"
            );
            heading.appendChild(document.createTextNode(" "));
            const hostState = document.createElement("span");
            hostState.className = `status-pill ${statusClass(host.state)}`;
            hostState.textContent = host.state;
            heading.appendChild(hostState);
            const ports = host.ports || [];
            if (!ports.length) {
                addText(section, "p", "No port observations were returned.", "data-note mb-0");
            } else {
                const tableWrap = document.createElement("div");
                tableWrap.className = "table-responsive";
                const table = document.createElement("table");
                table.className = "table table-cyber";
                const thead = document.createElement("thead");
                const header = document.createElement("tr");
                ["Port", "State", "Service", "Version", "Reason"].forEach((label) => addText(header, "th", label));
                thead.appendChild(header);
                table.appendChild(thead);
                const tbody = document.createElement("tbody");
                ports.forEach((port) => {
                    const row = document.createElement("tr");
                    const service = port.service || {};
                    addText(row, "td", `${port.protocol.toUpperCase()} ${port.port}`);
                    const stateCell = document.createElement("td");
                    const pill = addText(stateCell, "span", port.state, `status-pill ${statusClass(port.state)}`);
                    pill.setAttribute("aria-label", `Port state ${port.state}`);
                    row.appendChild(stateCell);
                    addText(row, "td", service.product || service.name || "Unidentified");
                    addText(row, "td", service.version || "—");
                    addText(row, "td", port.reason || "—");
                    tbody.appendChild(row);
                });
                table.appendChild(tbody);
                tableWrap.appendChild(table);
                section.appendChild(tableWrap);
            }
            results.appendChild(section);
        });

        const findings = scan.findings || [];
        addText(results, "h3", `Vulnerability findings (${findings.length})`, "h6 mt-4 mb-3");
        if (!findings.length) {
            addText(results, "p", "No vulnerability findings were recorded for this scan.", "data-note");
        }
        findings.forEach((finding) => {
            const item = document.createElement("article");
            item.className = "finding-result";
            const title = addText(
                item,
                "h4",
                `${finding.cve_id || finding.title} · ${finding.severity}`,
                "h6"
            );
            const classification = addText(
                title,
                "span",
                ` ${finding.classification}`,
                "status-pill status-warning ms-2"
            );
            classification.setAttribute("aria-label", `Finding classification ${finding.classification}`);
            addText(item, "p", finding.description);
            addText(item, "p", `Remediation: ${finding.remediation}`, "mb-0");
            results.appendChild(item);
        });
    }

    function updateView(scan) {
        activeScanId = scan.id;
        const progress = Math.max(0, Math.min(100, Number(scan.progress) || 0));
        progressBar.style.width = `${progress}%`;
        progressTrack.setAttribute("aria-valuenow", String(progress));
        progressLabel.textContent = `${progress}%`;
        status.textContent = `Scan #${scan.id} · ${scan.target} · ${scan.status} — ${scan.phase || "queued"}`;
        errorNode.textContent = scan.error || "";
        const active = ["queued", "running"].includes(scan.status);
        cancelButton.hidden = !active;
        reportLinks.hidden = scan.status !== "completed";
        if (scan.status === "completed") {
            document.getElementById("scan-csv-link").href = `/api/scans/${scan.id}/report.csv`;
            document.getElementById("scan-pdf-link").href = `/api/scans/${scan.id}/report.pdf`;
            renderFindings(scan);
        } else if (scan.status === "failed" || scan.status === "cancelled") {
            results.replaceChildren();
            if (scan.error) addText(results, "p", scan.error, "text-danger");
        }
    }

    async function checkHealth() {
        const badge = document.getElementById("scanner-health-status");
        const detail = document.getElementById("scanner-health-detail");
        try {
            const response = await fetch("/api/scans/health", {
                headers: { "X-CSRFToken": csrfToken },
                credentials: "same-origin",
            });
            const payload = await response.json();
            const scanner = payload.scanner || {};
            const nmap = scanner.nmap || {};
            const adapter = scanner.python_integration || {};
            let label = "Unavailable";
            if (scanner.status === "operational") label = "Ready";
            else if (nmap.status === "not_installed") label = "Nmap missing";
            else if (adapter.status === "not_installed") label = "Python integration missing";
            badge.className = `status-pill ${scanner.status === "operational" ? "status-success" : "status-warning"}`;
            badge.textContent = label;
            detail.textContent = `Nmap: ${nmap.status}${nmap.version ? ` (${nmap.version})` : ""} · Python integration: ${adapter.status}${adapter.version ? ` (${adapter.version})` : ""}`;
            if (!response.ok && !payload.scanner) {
                throw new Error(payload.error || `Health check failed (${response.status}).`);
            }
        } catch (error) {
            badge.className = "status-pill status-danger";
            badge.textContent = "Unavailable";
            detail.textContent = error.message;
        }
    }

    async function refreshHistory() {
        try {
            const payload = await request("/api/scans");
            historyBody.replaceChildren();
            if (!payload.scans.length) {
                const row = document.createElement("tr");
                addText(row, "td", "No network scans yet.", "data-note");
                row.firstElementChild.colSpan = 5;
                historyBody.appendChild(row);
                return;
            }
            payload.scans.forEach((scan) => {
                const row = document.createElement("tr");
                addText(row, "td", `#${scan.id}`);
                addText(row, "td", scan.target);
                const state = document.createElement("td");
                addText(state, "span", scan.status, `status-pill ${statusClass(scan.status)}`);
                row.appendChild(state);
                addText(row, "td", `${scan.progress || 0}%`);
                const action = document.createElement("td");
                const button = addText(action, "button", "Details", "btn btn-cyber-outline btn-sm");
                button.type = "button";
                button.addEventListener("click", () => showScan(scan.id));
                row.appendChild(action);
                historyBody.appendChild(row);
            });
        } catch (error) {
            historyBody.replaceChildren();
            const row = document.createElement("tr");
            const cell = addText(row, "td", error.message, "text-danger");
            cell.colSpan = 5;
            historyBody.appendChild(row);
        }
    }

    async function showScan(scanId) {
        try {
            const payload = await request(`/api/scans/${encodeURIComponent(scanId)}`);
            results.replaceChildren();
            errorNode.textContent = "";
            updateView(payload.scan);
            if (["queued", "running"].includes(payload.scan.status)) pollScan(scanId);
        } catch (error) {
            status.textContent = error.message;
        }
    }

    function pollScan(scanId) {
        window.clearTimeout(pollTimer);
        pollTimer = window.setTimeout(async () => {
            try {
                const payload = await request(`/api/scans/${encodeURIComponent(scanId)}`);
                if (activeScanId !== scanId) return;
                updateView(payload.scan);
                if (["queued", "running"].includes(payload.scan.status)) {
                    pollScan(scanId);
                } else {
                    await refreshHistory();
                }
            } catch (error) {
                status.textContent = error.message;
            }
        }, 1400);
    }

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        results.replaceChildren();
        errorNode.textContent = "";
        reportLinks.hidden = true;
        const portsText = document.getElementById("scan-ports").value.trim();
        const payload = {
            target: document.getElementById("scan-target").value,
            profile: "safe",
            authorization_confirmed: document.getElementById("authorization-confirmed").checked,
        };
        if (portsText) payload.ports = portsText.split(",").map((port) => Number(port.trim()));
        submitButton.disabled = true;
        try {
            const response = await request("/api/scans", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            updateView(response.scan);
            pollScan(response.scan.id);
            await refreshHistory();
        } catch (error) {
            status.textContent = "Scan request was not accepted.";
            errorNode.textContent = error.message;
            progressBar.style.width = "0%";
            progressTrack.setAttribute("aria-valuenow", "0");
        } finally {
            submitButton.disabled = false;
        }
    });

    cancelButton.addEventListener("click", async () => {
        if (!activeScanId) return;
        cancelButton.disabled = true;
        errorNode.textContent = "";
        try {
            const response = await request(`/api/scans/${encodeURIComponent(activeScanId)}/cancel`, { method: "POST" });
            updateView(response.scan);
        } catch (error) {
            errorNode.textContent = error.message;
        } finally {
            cancelButton.disabled = false;
        }
    });

    checkHealth();
    refreshHistory();
    const requestedScan = new URLSearchParams(window.location.search).get("scan_id");
    if (requestedScan && /^\d+$/.test(requestedScan)) showScan(requestedScan);
});
