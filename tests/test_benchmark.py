import unittest

from benchmark import calculate_metrics


class BenchmarkMetricTests(unittest.TestCase):
    def test_confusion_matrix_and_metrics(self):
        result = calculate_metrics([0, 0, 1, 1], [0, 1, 1, 0])
        self.assertEqual(
            (result["tp"], result["tn"], result["fp"], result["fn"]),
            (1, 1, 1, 1),
        )
        self.assertAlmostEqual(result["precision"], 0.5)
        self.assertAlmostEqual(result["recall"], 0.5)
        self.assertAlmostEqual(result["f1"], 0.5)
        self.assertAlmostEqual(result["false_positive_rate"], 0.5)
        self.assertAlmostEqual(result["accuracy"], 0.5)

    def test_empty_predictions_are_safe(self):
        result = calculate_metrics([0, 1], [0, 0])
        self.assertEqual(result["precision"], 0.0)
        self.assertEqual(result["recall"], 0.0)
        self.assertEqual(result["f1"], 0.0)


if __name__ == "__main__":
    unittest.main()
