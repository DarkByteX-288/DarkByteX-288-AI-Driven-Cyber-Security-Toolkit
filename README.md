# AI-Driven Cyber Security Toolkit

Password Strength Evaluation · Phishing URL Detection · Attack Simulation · Adaptive Defense

A Flask web application that combines rule-based security analysis with
machine learning to help users understand and improve their password
hygiene and spot phishing links, backed by a full dashboard, history,
reporting, and settings experience.

---

## 1. Features

- **Authentication** — registration, login/logout, "remember me", hashed
  passwords (PBKDF2-SHA256 via Werkzeug), protected routes.
- **AI Password Strength Evaluator** — entropy, dictionary/keyboard-pattern/
  sequential/repeated-character detection, a RandomForest ML prediction,
  a 0-100 strength score, and tailored recommendations.
- **Attack Simulation** — dictionary, brute-force, hybrid, pattern, and
  keyboard-walk attack time estimates against the password's characteristics
  (never against the actual password value; nothing is cracked for real).
- **AI Phishing URL Detection** — HTTPS check, IP-address hosts, `@` symbols,
  URL shorteners, suspicious keywords, subdomain counts, TLD reputation, and
  a RandomForest ML verdict (Safe / Suspicious / Phishing) with reasons and
  recommendations. Analysis is purely lexical — the URL is never visited.
- **Dashboard** — aggregate stats, pie/bar charts (Chart.js), a security
  score ring, and recent activity.
- **History** — search, filter, and delete past analyses.
- **Settings** — dark/light theme, CSV/PDF export, clear history, one-click
  AI model retraining, database & app info.
- **Reports** — CSV exports and a PDF security summary report.

## 2. Tech Stack

| Layer          | Tools |
|----------------|-------|
| Frontend       | HTML5, CSS3, Vanilla JS, Bootstrap 5, Chart.js, Font Awesome |
| Backend        | Python 3.12, Flask, Flask-SQLAlchemy, Flask-Login, Flask-Migrate, Flask-WTF, Flask-Limiter |
| Database       | SQLite |
| Machine Learning | scikit-learn (RandomForest), pandas, NumPy, Joblib |
| Reports        | ReportLab (PDF), built-in `csv` module |

## 3. Project Structure

```
/project
├── app.py                     # Flask application factory
├── config.py                  # Environment-based configuration
├── requirements.txt
├── models/                    # SQLAlchemy models (User, PasswordAnalysis, URLAnalysis, AttackLog, SystemLog, UserSettings)
├── routes/                    # Blueprints (auth, main, password_checker, url_checker, history, settings, reports)
├── services/                  # Business logic: feature extraction, scoring, attack simulation, recommendations
├── ml/                        # Dataset generation, model training, model loader
├── utils/                     # Forms, report generation, security helpers
├── static/{css,js,images}/
├── templates/                 # Jinja2 templates (dark-themed, responsive)
├── instance/                  # SQLite database lives here at runtime
├── datasets/                  # Generated training datasets (CSV)
├── trained_models/            # Trained Joblib model files (.pkl)
└── tests/                     # Pytest unit tests
```

## 4. Installation

### Standard Python setup

```bash
cd project
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

### Windows / Conda setup

If `pip install -r requirements.txt` fails on Windows due to `scikit-learn` build requirements,
use a Conda environment and install the ML dependencies from conda-forge:

```powershell
conda create -p D:\conda_envs\attaullah python=3.11 -y
conda install -p D:\conda_envs\attaullah -c conda-forge scikit-learn==1.5.1 numpy pandas joblib -y
D:\conda_envs\attaullah\python.exe -m pip install -r requirements.txt --no-cache-dir
D:\conda_envs\attaullah\python.exe app.py
```

Then open **http://127.0.0.1:5000** in your browser.

On first run, the app automatically:
1. Creates the SQLite database and all tables.
2. Generates synthetic training datasets (`datasets/*.csv`) if missing.
3. Trains and saves both RandomForest models (`trained_models/*.pkl`) if missing.

### Re-training models manually (optional)

```bash
python ml/generate_password_dataset.py && python ml/train_password_model.py
python ml/generate_url_dataset.py && python ml/train_url_model.py
```

Or use **Settings → AI Model Management → Retrain AI Models** in the UI.

### Running tests

```bash
D:\conda_envs\attaullah\python.exe -m pip install pytest --no-cache-dir
D:\conda_envs\attaullah\python.exe -m pytest tests/ -v
```

## 5. About the training data

Real breached-password corpora and phishing-URL feeds (e.g. rockyou.txt,
PhishTank, OpenPhish) carry licensing/attribution and distribution
restrictions that don't belong bundled in a public repo. Instead,
`ml/generate_password_dataset.py` and `ml/generate_url_dataset.py`
procedurally generate structurally representative examples across the full
spectrum (dictionary words, keyboard walks, random strong strings /
IP-hosted links, URL shorteners, brand-lookalike domains, etc.) using the
**same rule-based features** the app extracts at inference time. This keeps
the project dependency-free and legally unencumbered while still training
genuinely predictive models. For a production deployment, swap in a real
labeled corpus (e.g. a HIBP-derived password list, PhishTank/OpenPhish feed)
by replacing the CSVs in `datasets/` and re-running the training scripts —
the feature extraction and model code needs no changes.

## 6. Security notes

- Passwords are **never stored in plaintext** — only derived, non-reversible
  metrics (length, entropy, boolean flags) are persisted.
- URL analysis is **purely structural/lexical** — the app never makes a
  network request to the URL being analyzed.
- CSRF protection (Flask-WTF), secure session cookies, security response
  headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`),
  parameterized queries (via SQLAlchemy ORM), and basic rate limiting
  (Flask-Limiter) are enabled by default.
- Set `SECRET_KEY` and `FORCE_HTTPS=true` environment variables before any
  real deployment; the defaults in `config.py` are for local development only.

## 7. Known limitations / scope notes

This is an educational / portfolio-grade project, not a hardened production
security product:

- The bundled datasets are synthetic (see §5) rather than sourced from real
  breach/phishing corpora, so reported model accuracy reflects how well the
  model fits the synthetic generation rules, not real-world phishing traffic.
- Crack-time estimates use a fixed, published "typical GPU" guess-rate
  assumption for teaching purposes — real attacker capability varies widely
  with hash algorithm, hardware, and salting.
- Rate limiting uses in-memory storage (`memory://`), which resets on
  restart and doesn't scale across multiple worker processes — swap in Redis
  (`RATELIMIT_STORAGE_URI`) for production.
- No email verification or password-reset flow is implemented.
