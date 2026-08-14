from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


STREAMLIT_AVAILABLE = importlib.util.find_spec("streamlit") is not None


@unittest.skipUnless(STREAMLIT_AVAILABLE, "Streamlit is installed by the app/CI extra")
class DashboardSmokeTests(unittest.TestCase):
    def test_default_compromised_view_renders_metrics_charts_and_evidence(self):
        from streamlit.testing.v1 import AppTest

        root = Path(__file__).resolve().parents[1]
        app = AppTest.from_file(str(root / "dashboard" / "app.py")).run(timeout=45)
        self.assertFalse(app.exception)
        self.assertEqual(len(app.get("metric")), 6)
        self.assertGreaterEqual(len(app.get("plotly_chart")), 3)
        self.assertGreaterEqual(len(app.get("table")), 1)


if __name__ == "__main__":
    unittest.main()
