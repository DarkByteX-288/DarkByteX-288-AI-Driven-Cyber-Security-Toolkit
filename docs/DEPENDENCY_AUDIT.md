# Dependency Audit

## Python and resolution

The verified runtime is Python 3.11.7 on Windows. The directly pinned packages in `requirements.txt` installed successfully in a newly created virtual environment. `requirements-lock.txt` records the resolved tested runtime and transitive packages; `requirements-dev.txt` adds test and audit tools. Python 3.12 has not been exercised in this workspace and is not claimed as a tested runtime.

The selected stack retains Flask-SQLAlchemy 3.x and SQLAlchemy 2.0, Flask-Migrate 4.x, scikit-learn 1.5.1, pandas 2.2.2, NumPy 1.26.4, Joblib 1.4.2, and ReportLab 4.2.2. Installation succeeded together on Python 3.11.7. scikit-learn's SciPy requirement is resolved and pinned in the lock file. Bounded hostname resolution uses `dnspython`; Nmap integration is `python-nmap`, while the Nmap executable remains a separate system dependency.

## Security audit

`pip-audit -r requirements.txt` initially identified vulnerabilities in Flask 3.0.3, Werkzeug 3.0.3, and python-dotenv 1.0.1. These were raised to the audit-reported fixed versions (Flask 3.1.3, Werkzeug 3.1.9, python-dotenv 1.2.2). After installation, the audit reported **no known vulnerabilities** for `requirements.txt`. Re-run the audit before deployment because advisory data changes over time.

## Commands

```powershell
python -m pip install -r requirements-lock.txt
python -m pip install -r requirements-dev.txt
python -m pip_audit -r requirements.txt
```

Regenerate the lock file only from a clean Python 3.11 environment after reviewing dependency changes. Do not blanket-upgrade packages: verify compatibility and run tests after changing a pin. No optional XGBoost dependency is installed or required.
