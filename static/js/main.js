document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".cyber-alert").forEach((element) => {
        window.setTimeout(() => {
            if (window.bootstrap) {
                window.bootstrap.Alert.getOrCreateInstance(element).close();
            }
        }, 6500);
    });

    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            const button = form.querySelector('button[type="submit"], input[type="submit"]');
            if (!button || button.dataset.noSpinner !== undefined || button.disabled) return;
            button.dataset.originalText = button.innerHTML;
            if (button.tagName === "BUTTON") {
                button.innerHTML = '<span class="loading-spinner" aria-hidden="true"></span> Processing…';
            }
            button.disabled = true;
        });
    });

    const toggle = document.querySelector("[data-sidebar-toggle]");
    const backdrop = document.querySelector("[data-sidebar-close]");
    const closeSidebar = () => {
        document.body.classList.remove("sidebar-open");
        if (toggle) toggle.setAttribute("aria-expanded", "false");
    };
    if (toggle) {
        toggle.addEventListener("click", () => {
            const opened = document.body.classList.toggle("sidebar-open");
            toggle.setAttribute("aria-expanded", String(opened));
        });
    }
    if (backdrop) backdrop.addEventListener("click", closeSidebar);
    document.querySelectorAll("[data-password-toggle]").forEach((button) => {
        const input = document.getElementById(button.dataset.passwordToggle);
        const icon = button.querySelector("i");
        if (!input || !icon) return;
        button.addEventListener("click", () => {
            const visible = input.type === "password";
            input.type = visible ? "text" : "password";
            button.setAttribute("aria-pressed", String(visible));
            button.setAttribute("aria-label", visible ? "Hide password" : "Show password");
            icon.classList.toggle("fa-eye", !visible);
            icon.classList.toggle("fa-eye-slash", visible);
        });
    });
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeSidebar();
        if (event.key === "/" && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
            const search = document.querySelector(".top-search input[type=search]");
            if (search) {
                event.preventDefault();
                search.focus();
            }
        }
    });
});

function cyberColorFor(category) {
    const colors = {
        "Very Weak": "#ef4444",
        "Weak": "#f59e0b",
        "Moderate": "#eab308",
        "Strong": "#22c55e",
        "Very Strong": "#22d3ee",
        "Safe": "#22c55e",
        "Suspicious": "#f59e0b",
        "Phishing": "#ef4444",
        "Critical": "#dc2626",
        "High": "#ef4444",
        "Medium": "#f59e0b",
        "Low": "#22c55e",
        "Informational": "#22d3ee",
    };
    return colors[category] || "#3b82f6";
}
