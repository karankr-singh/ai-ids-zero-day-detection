# UNSW-NB15 model optimization

Run model comparison, threshold sensitivity, and feature permutation analysis
using only the official **training partition**:

```powershell
python -m evaluation.optimize_unsw_nb15 --train-csv datasets/unsw_nb15/UNSW_NB15_training-set.csv
```

If the Zenodo filenames were reversed on download, pass the actual path returned
as the training partition by `download_dataset()` (the larger 175,341-row file).

The experiment:
- fits preprocessing and models on normal-labeled training rows only;
- calibrates thresholds on a disjoint normal-only subset;
- uses labeled attacks and a disjoint normal subset from the official training
  partition only for validation-based model/threshold selection;
- compares Isolation Forest, novelty Local Outlier Factor, and One-Class SVM;
- sweeps calibration false-positive targets of 1%, 2.5%, 5%, 7.5%, 10%, and 15%;
- computes Isolation Forest feature permutation importance on training-side
  validation rows;
- never opens or reads the official test partition.

Output: `results/unsw_nb15/optimization/unsw_nb15_optimization.json`.

After selecting and freezing a model and operating threshold, run the existing
`evaluation.run_unsw_nb15` once on the official test partition. Do not use
the test results to revise model choice or threshold. The test benchmark script
remains unchanged.
