# URL detection: data, training, and operations

## Dataset assessment

The training input is `datasets/url_phishing_dataset_100k.csv`. It has 100,000 rows, 37 columns, labels evenly split between `0`/`legitimate` and `1`/`phishing`, and 20 attack-category values. The recorded origins are `synthetic` and `synthetic_pattern_using_public_domain_names`; none of the records is represented as independently verified real-world threat intelligence.

The ingestion pipeline validates HTTP(S) URL syntax and labels, reports missing/invalid rows, removes duplicate URLs and contradictory URL labels, verifies the optional `label_name`, and derives all classifier features from the URL itself. Supplied feature columns, attack categories, labels other than the target, and origin metadata are never model inputs. This avoids label/feature inconsistency and target leakage. Preserved attack category and origin values are analysis metadata only.

Data inspection found 100,000 unique, syntactically valid URLs and no blank fields. The supplied numeric features differ from this application's deterministic extractor for some columns, so training recomputes rather than trusts them. All rows are synthetic or synthetic-pattern examples; domain-separated results measure generalization across these generated domains only, not real-world accuracy.

## Train, evaluate, and artifacts

From the project directory, with `requirements.txt` installed:

```powershell
python ml/train_url_model.py
```

The pipeline uses approximate registrable-domain groups (a local suffix list, without external lookups) and a deterministic weighted assignment that balances overall rows, labels, and the synthetic attack categories as far as indivisible domain groups allow. It selects a candidate on a validation split, fits sigmoid calibration on validation predictions, tunes a decision threshold to target at least 85% validation recall while minimizing false-positive rate, and evaluates once on a domain-disjoint test split. Available candidates are Random Forest, HistGradientBoosting, Gradient Boosting, numeric-feature Logistic Regression, and URL-character n-gram Logistic Regression. XGBoost is compared only if it is already installed. Exact row targets can be infeasible when a registrable domain has many records; actual split sizes and category counts are recorded in the report.

Generated artifacts are kept under `datasets/url_detection_artifacts/`:

- `train.csv`, `validation.csv`, `test.csv`: domain-separated, recomputed features plus URL, label, and synthetic-source metadata.
- `model_evaluation.json`: data quality, exact split sizes, candidate validation metrics, selected model, calibration disclosure, test metrics, and feature importance.
- `confusion_matrix.csv` and `feature_importance.csv`: held-out confusion matrix and model explanation where supported.

The selected calibrated estimator and ordered feature schema are saved atomically to `trained_models/url_model.pkl`. The runtime rejects older or incompatible URL model bundles and retrains from the 100k input. The password-analysis model and its training path are unchanged.

## Current evaluation and limitations

The current grouped split contains 69,932 training rows, 15,044 validation rows, and 15,024 test rows, with no registrable domain crossing splits. On the untouched synthetic, domain-disjoint test set, the selected Random Forest achieved 76.90% accuracy, 79.10% precision, 74.29% recall, 0.7662 F1, and 0.7911 ROC-AUC at the validation-selected threshold (0.9284). Its test false-positive rate was 20.38% and false-negative rate was 25.71%. These results show substantial domain shift and are not an acceptable basis for claiming reliable real-world detection.

The validation threshold met its recall target on validation, but did not generalize to the held-out domains. The `ip_based` and `url_shortener_pattern` categories also have no training rows in this grouped split because examples are concentrated in indivisible domain groups. The runtime therefore treats an ML-only phishing prediction without independent URL evidence as `UNKNOWN / INSUFFICIENT DATA`; this reduces unsupported warnings but does not repair the model's measured generalization. Obtain an independently sourced, correctly labeled corpus and improve domain/category coverage before using the model for blocking or making real-world accuracy claims. The exact audit and metrics are in `model_evaluation.json`.

## Runtime behavior and limitations

The existing authenticated `/url-checker` route and analysis-history schema remain intact. Analysis combines deterministic structural/domain heuristics with the calibrated synthetic-data model. The displayed 0–100 hybrid risk score is not a probability. Model confidence is exposed separately and explicitly scoped to synthetic validation data. Strongly inconclusive evidence is labeled `UNKNOWN / INSUFFICIENT DATA`; lack of reputation hits is not treated as proof of safety.

Structural/domain checks are local and do not fetch the submitted URL. Brand similarity, Unicode/Punycode, URL patterns, and the suspicious-TLD watchlist are heuristics, not domain ownership or registration-age verification. No domain-age or certificate reputation data is fabricated.

TLS and redirect checks are disabled by default. To enable bounded checks against public hosts, set `URL_ENABLE_NETWORK_CHECKS=true`. The checks use a short timeout, only ports 80/443, block loopback/private/non-global IP addresses after DNS resolution, pin the resolved IP for each connection, validate HTTPS certificates/hostnames, and cap redirects and URL length. These checks are best-effort; unavailable results remain unavailable, not safe. TLS validity does not establish site legitimacy.

Threat-intelligence providers are optional and queried server-side only when their API key is configured in the environment:

| Provider | Environment variable |
|---|---|
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_API_KEY` |
| VirusTotal | `VIRUSTOTAL_API_KEY` |
| PhishTank | `PHISHTANK_API_KEY` |
| URLhaus | `URLHAUS_AUTH_KEY` |

Configured providers receive the submitted URL. Keep keys out of source control and configure them only when this data sharing is acceptable. Provider timeouts, rate limits, and failures are surfaced as unavailable checks; the local detector continues to work without credentials.

## Testing

Run all project tests:

```powershell
python -m pytest tests -q
```

The URL tests cover ordinary and complex URLs, common safe-looking flows, domain/brand heuristics, IDNs, malformed inputs, risk evidence, confidence calibration disclosure, and private-address blocking. No test visits a submitted destination or uses live threat data.
