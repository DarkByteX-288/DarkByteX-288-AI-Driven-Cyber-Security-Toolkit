/**
 * static/js/password_checker.js
 * Purely cosmetic client-side "typing hint" bar - the authoritative analysis
 * always happens server-side in services/password_service.py. This never
 * sends the password anywhere; it only reacts locally in the browser.
 */

document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("password-input");
    const hintBar = document.getElementById("live-hint-bar");
    const hintLabel = document.getElementById("live-hint-label");
    const toggleBtn = document.getElementById("toggle-password-visibility");

    if (toggleBtn && input) {
        toggleBtn.addEventListener("click", () => {
            const visible = input.type === "password";
            input.type = visible ? "text" : "password";
            toggleBtn.setAttribute("aria-pressed", String(visible));
            toggleBtn.setAttribute("aria-label", visible ? "Hide password" : "Show password");
            toggleBtn.querySelector("i").classList.toggle("fa-eye", !visible);
            toggleBtn.querySelector("i").classList.toggle("fa-eye-slash", visible);
        });
    }

    if (input && hintBar && hintLabel) {
        input.addEventListener("input", () => {
            const val = input.value;
            let score = 0;
            if (val.length >= 8) score += 25;
            if (val.length >= 12) score += 15;
            if (/[A-Z]/.test(val)) score += 15;
            if (/[a-z]/.test(val)) score += 15;
            if (/[0-9]/.test(val)) score += 15;
            if (/[^A-Za-z0-9]/.test(val)) score += 15;
            score = Math.min(score, 100);

            let color = "#ef4444";
            let label = "Very Weak";
            if (score >= 80) { color = "#26d3d3"; label = "Very Strong"; }
            else if (score >= 60) { color = "#21c98a"; label = "Strong"; }
            else if (score >= 40) { color = "#f7d774"; label = "Moderate"; }
            else if (score >= 20) { color = "#f7a934"; label = "Weak"; }

            hintBar.style.width = val.length ? score + "%" : "0%";
            hintBar.style.backgroundColor = color;
            hintLabel.textContent = val.length ? `Live hint: ${label}` : "Start typing to see a live hint...";
        });
    }
});
