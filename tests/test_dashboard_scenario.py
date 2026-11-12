import unittest

from dashboard import Dashboard


class DashboardScenarioTests(unittest.TestCase):
    def setUp(self):
        self.dashboard = Dashboard.__new__(Dashboard)
        self.dashboard._scenario = {
            "status": "STANDBY",
            "key": None,
            "label": "No active scenario",
            "description": "",
            "target": 0,
            "generated": 0,
            "candidates": 0,
        }
        self.dashboard._refresh = lambda: None

    def test_scenario_update_sets_running_state_and_resets_counts(self):
        self.dashboard.update_scenario({
            "status": "RUNNING",
            "key": "port_scan",
            "label": "Port Scan",
            "description": "Synthetic port scan",
            "target": 12,
            "generated": 0,
            "candidates": 0,
        })
        self.assertEqual(self.dashboard._scenario["status"], "RUNNING")
        self.assertEqual(self.dashboard._scenario["label"], "Port Scan")
        self.assertEqual(self.dashboard._scenario["target"], 12)

    def test_matching_attack_records_update_generated_and_candidate_counts(self):
        self.dashboard.update_scenario({
            "status": "RUNNING",
            "key": "ddos",
            "target": 2,
            "generated": 0,
            "candidates": 0,
        })
        self.dashboard.record_scenario_record({"pkt_type": "ddos"}, True)
        self.dashboard.record_scenario_record({"pkt_type": "ddos"}, False)
        self.assertEqual(self.dashboard._scenario["generated"], 2)
        self.assertEqual(self.dashboard._scenario["candidates"], 1)


    def test_rendered_panel_shows_progress_and_candidate_count(self):
        self.dashboard.update_scenario({
            "status": "COMPLETE",
            "key": "port_scan",
            "label": "Port Scan",
            "target": 12,
            "generated": 12,
            "candidates": 9,
        })
        panel = self.dashboard._render_scenario()
        rendered = panel.renderable.plain
        self.assertIn("Port Scan", rendered)
        self.assertIn("COMPLETE", rendered)
        self.assertIn("RECORDS 12/12", rendered)
        self.assertIn("CANDIDATES 9", rendered)

    def test_unrelated_or_completed_records_are_ignored(self):
        self.dashboard.update_scenario({
            "status": "RUNNING",
            "key": "port_scan",
            "generated": 0,
            "candidates": 0,
        })
        self.dashboard.record_scenario_record({"pkt_type": "ddos"}, True)
        self.dashboard.update_scenario({"status": "COMPLETE"})
        self.dashboard.record_scenario_record({"pkt_type": "port_scan"}, True)
        self.assertEqual(self.dashboard._scenario["generated"], 0)
        self.assertEqual(self.dashboard._scenario["candidates"], 0)


if __name__ == "__main__":
    unittest.main()
