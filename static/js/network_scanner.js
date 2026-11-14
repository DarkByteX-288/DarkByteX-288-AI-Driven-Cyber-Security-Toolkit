document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("network-scan-form");
    const submitButton = document.getElementById("start-scan-button");
    const cancelButton = document.getElementById("cancel-scan-button");
    const status = document.getElementById("scan-status");
    const progressBar = document.getElementById("scan-progress-bar");
    const results = document.getElementById("scan-results");
    const historyList = document.getElementById("scan-history");
    const reportLinks = document.getElementById("scan-report-links");
    const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
    let activeScanId = null;
    let pollTimer = null;

    async function request(url, options = {}) {
        const headers = { "X-CSRFToken": csrfToken, ...(options.headers || {}) };
        const response = await fetch(url, { ...options, headers });
        const contentType = response.headers.get("content-type") || "";
        const payload = contentType.includes("application/json") ? await response.json() : {};
        if (!response.ok) {
            throw new Error(payload.error || `Request failed (${response.status}).`);
        }
        return payload;
    }

    function addText(parent, tag, text, className) {
        const element = document.createElement(tag);
        element.textContent = text;
        if (className) element.className = className;
        parent.appendChild(element);
        return element;
    }

    function renderFindings(scan) {
        results.replaceChildren();
        (scan.hosts || []).forEach((host) => {
            const section = document.createElement("section");
            section.className = "mb-3";
            addText(section, "h6", `${host.address} ${host.hostname ? `(${host.hostname})` : ""} - ${host.state}`);
            (host.ports || []).forEach((port) => {
                const service = port.service || {};
                addText(
                    section,
                    "p",
                    `TCP ${port.port}: ${service.product || service.name || "unknown service"} ${service.version || ""}`.trim(),
                    "mb-1"
                );
            });
            results.appendChild(section);
        });
        const findings = scan.findings || [];
        addText(results, "h6", `Findings (${findings.length})`);
        findings.forEach((finding) => {
            const item = document.createElement("div");
            item.className = "border rounded p-2 mb-2";
            addText(
                item,
                "strong",
                `${finding.classification.toUpperCase()} - ${finding.cve_id || finding.title} - ${finding.severity}` +
                    (finding.cvss_score === null || finding.cvss_score === undefined
                        ? ""
                        : ` - CVSS ${finding.cvss_version || "?"}: ${finding.cvss_score}`)
            );
            addText(item, "p", finding.description, "mb-1");
            addText(item, "p", `Remediation: ${finding.remediation}`, "mb-0");
            results.appendChild(item);
        });
    }

    function updateView(scan) {
        activeScanId = scan.id;
        progressBar.style.width = `${scan.progress || 0}%`;
        status.textContent = `Scan ${scan.id}: ${scan.status} — ${scan.phase} (${scan.progress || 0}%)`;
        const active = ["queued", "running"].includes(scan.status);
        cancelButton.hidden = !active;
        if (scan.error) addText(results, "p", scan.error, "text-danger");
        if (scan.status === "completed") {
            reportLinks.hidden = false;
            document.getElementById("scan-csv-link").href = `/api/scans/${scan.id}/report.csv`;
            document.getElementById("scan-pdf-link").href = `/api/scans/${scan.id}/report.pdf`;
            renderFindings(scan);
        }
    }

    async function refreshHistory() {
        try {
            const payload = await request("/api/scans");
            historyList.replaceChildren();
            if (!payload.scans.length) {
                addText(historyList, "li", "No network scans yet.");
                return;
            }
            payload.scans.forEach((scan) => {
                const item = document.createElement("li");
                const link = document.createElement("button");
                link.type = "button";
                link.className = "btn btn-link p-0";
                link.textContent = `#${scan.id} ${scan.target} — ${scan.status}`;
                link.addEventListener("click", () => showScan(scan.id));
                item.appendChild(link);
                historyList.appendChild(item);
            });
        } catch (error) {
            historyList.replaceChildren();
            addText(historyList, "li", error.message, "text-danger");
        }
    }

    async function showScan(scanId) {
        try {
            const payload = await request(`/api/scans/${scanId}`);
            results.replaceChildren();
            reportLinks.hidden = true;
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
                const payload = await request(`/api/scans/${scanId}`);
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
        }, 1200);
    }

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        results.replaceChildren();
        reportLinks.hidden = true;
        const portsText = document.getElementById("scan-ports").value.trim();
        const payload = {
            target: document.getElementById("scan-target").value,
            profile: "safe",
            authorization_confirmed: document.getElementById("authorization-confirmed").checked,
        };
        if (portsText) {
            payload.ports = portsText.split(",").map((port) => Number(port.trim()));
        }
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
            status.textContent = error.message;
            progressBar.style.width = "0%";
        } finally {
            submitButton.disabled = false;
        }
    });

    cancelButton.addEventListener("click", async () => {
        if (!activeScanId) return;
        cancelButton.disabled = true;
        try {
            const response = await request(`/api/scans/${activeScanId}/cancel`, { method: "POST" });
            updateView(response.scan);
        } catch (error) {
            status.textContent = error.message;
        } finally {
            cancelButton.disabled = false;
        }
    });

    refreshHistory();
});
