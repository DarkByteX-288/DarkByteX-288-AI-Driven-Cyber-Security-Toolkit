/**
 * static/js/main.js
 * Global JS: theme sync helper, alert auto-dismiss, form loading-state helper.
 */

document.addEventListener("DOMContentLoaded", () => {
    // Auto-dismiss alerts after 6 seconds
    document.querySelectorAll(".cyber-alert").forEach((el) => {
        setTimeout(() => {
            const alert = bootstrap.Alert.getOrCreateInstance(el);
            alert.close();
        }, 6000);
    });

    // Show a spinner + disable submit button on any form submit
    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            const btn = form.querySelector("button[type=submit]");
            if (btn && !btn.dataset.noSpinner) {
                btn.dataset.originalText = btn.innerHTML;
                btn.innerHTML = '<span class="loading-spinner"></span> Processing...';
                btn.disabled = true;
            }
        });
    });
});

/** Helper: map a strength/verdict category to a CSS color variable. */
function cyberColorFor(category) {
    const map = {
        "Very Weak": "#ef4444",
        "Weak": "#f7a934",
        "Moderate": "#f7d774",
        "Strong": "#21c98a",
        "Very Strong": "#26d3d3",
        "Safe": "#21c98a",
        "Suspicious": "#f7a934",
        "Phishing": "#ef4444",
    };
    return map[category] || "#2f7dff";
}
