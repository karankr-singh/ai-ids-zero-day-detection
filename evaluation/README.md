# UNSW-NB15 benchmark evaluation

This is a separate, reproducible benchmark path. It does not change the live
packet simulator or the current 10-feature detector.

## 1. Obtain the dataset

Use the UNSW Canberra Cyber official UNSW-NB15 dataset page:

https://research.unsw.edu.au/projects/unsw-nb15-dataset

Download the labeled CSV training and testing files (commonly named
\`UNSW_NB15_training-set.csv\` and \`UNSW_NB15_testing-set.csv\`). Keep the
original files unchanged and place them in a local directory such as
\`datasets/unsw_nb15/\`. Do not commit the dataset to Git.

The runner expects both CSVs to contain a numeric binary \`label\` column
(0 = normal, 1 = attack). The optional \`attack_cat\` column is used only for
per-category reporting. It accepts the labeled CSV format, not the raw
feature files without labels.

## 2. Install dependencies

From the repository root:

\`\`\`bash
python -m pip install -r requirements.txt
\`\`\`

## 3. Run the benchmark

\`\`\`bash
python -m evaluation.run_unsw_nb15 ^
  --train-csv datasets/unsw_nb15/UNSW_NB15_training-set.csv ^
  --test-csv datasets/unsw_nb15/UNSW_NB15_testing-set.csv ^
  --output-dir results/unsw_nb15
\`\`\`

On Linux/macOS, replace the PowerShell continuation character \`^\` with
\`\\\`.

Optional controls:

- \`--seed 42\`: deterministic normal-row split and model seed.
- \`--validation-fraction 0.20\`: fraction of normal training rows reserved for threshold calibration.
- \`--target-fpr 0.05\`: lower quantile of normal-only calibration scores used as the anomaly threshold.
- \`--estimators 200\`: Isolation Forest tree count.
- \`--top-k 100\`: number of highest anomaly-ranked test rows used for precision@k.

## 4. Split and leakage policy

1. The official training CSV is separated by its provided binary label.
2. Attack-labeled training rows are excluded from model fitting and threshold calibration.
3. Normal training rows are split into a fitting subset and a normal-only calibration subset.
4. Preprocessing (median imputation, scaling, and one-hot encoding) is fitted only on the fitting subset.
5. The threshold is selected from calibration scores only.
6. The official testing CSV is scored once for final metrics. It is never used to fit preprocessing, the model, or the threshold.

The official test split remains intact. Do not repeatedly tune hyperparameters against its metrics and then describe the same result as an untouched final test.

## 5. Output

The runner writes \`results/unsw_nb15/unsw_nb15_metrics.json\` with:

- ROC-AUC using negative Isolation Forest scores (larger = more attack-like)
- precision, recall, F1 and accuracy at the calibrated threshold
- precision@K among the most anomalous test records
- TN, FP, FN, TP, false-positive rate and false-negative rate
- per-attack-category recall when \`attack_cat\` is present
- threshold, split sizes, feature names, dataset SHA-256 hashes, seed and library versions

Isolation Forest scores are not probabilities. Precision@K is a ranking metric,
not a thresholded classification metric. A result file is evidence of a run
only when the referenced source CSVs and their hashes are retained.

## 6. Interpretation

A 5% target FPR is a calibration setting, not a promise that the official test
FPR will be 5%. The observed test FPR must be reported as measured. Results
describe this model and this dataset split only; they do not establish
production-network or universal zero-day detection capability.
