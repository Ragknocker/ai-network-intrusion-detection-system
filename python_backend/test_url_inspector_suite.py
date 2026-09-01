import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from modules.url_inspector.url_capture import capture_and_parse_url, normalize_url
from modules.url_inspector.url_features import extract_url_static_features, calculate_str_entropy
from modules.url_inspector.blacklist_checker import check_url_blacklists
from modules.url_inspector.domain_intelligence import get_domain_intel_backend
from modules.url_inspector.ml_url_classifier import classify_url_ml_backend
from modules.url_inspector.feedback_retrainer import record_analyst_feedback, trigger_model_retraining, calculate_model_drift
from modules.url_inspector.http_inspector import inspect_http_payload_backend
from modules.function_inspector.api_monitor import monitor_system_call_backend
from modules.function_inspector.behavior_analyzer import analyze_process_behavior_backend
from api import handle_api_request

class TestUrlInspectorBackend(unittest.TestCase):
    def test_url_capture_parsing(self):
        res = capture_and_parse_url("http://secure-paypal-login.xyz/login.php?id=123")
        self.assertEqual(res["hostname"], "secure-paypal-login.xyz")
        self.assertEqual(res["scheme"], "http")

    def test_url_normalization_and_punycode(self):
        norm, meta = normalize_url("http://%73%65%63%75%72%65-paypal%2ecom/login#fragment")
        self.assertNotIn("#fragment", norm)
        self.assertTrue(meta["percent_decoded"])

        puny_norm, puny_meta = normalize_url("http://xn--pypal-4ve.com/login")
        self.assertTrue(puny_meta["is_punycode"])

    def test_url_feature_extraction(self):
        feats = extract_url_static_features("http://secure-paypal-login.xyz/login.php")
        self.assertIn("paypal", feats["suspicious_keywords"])
        self.assertFalse(feats["has_https"])
        self.assertGreater(feats["entropy"], 3.0)
        self.assertIn("beaconing_periodicity_score", feats["network_context"])

    def test_stage1_allowlist_prefilter(self):
        allow_res = check_url_blacklists("https://google.com/search?q=nids")
        self.assertTrue(allow_res["is_allowlisted"])
        self.assertEqual(allow_res["stage1_verdict"], "ALLOW")
        self.assertEqual(allow_res["score"], 0)

    def test_blacklist_checker(self):
        bl = check_url_blacklists("http://secure-paypal-login.xyz/login.php")
        self.assertEqual(bl["score"], 100)
        self.assertTrue(len(bl["matches"]) > 0)
        self.assertEqual(bl["stage1_verdict"], "BLOCK")

    def test_domain_intelligence(self):
        intel = get_domain_intel_backend("secure-paypal-login.xyz")
        self.assertLess(intel["domain_age_days"], 30)
        self.assertFalse(intel["ssl_valid"])

    def test_ml_url_classification_and_reasons(self):
        feats = extract_url_static_features("http://secure-paypal-login.xyz/login.php")
        ml = classify_url_ml_backend(feats)
        self.assertGreater(ml["score"], 40)
        self.assertTrue(len(ml["reasons"]) > 0)
        self.assertIn("feature_importances", ml)

    def test_feedback_store_and_drift_tracker(self):
        fb = record_analyst_feedback("http://malicious-test.org", 85, "Confirmed Malicious", "Confirmed C2 host")
        self.assertEqual(fb["status"], "success")

        retrain = trigger_model_retraining()
        self.assertEqual(retrain["status"], "completed")

        drift = calculate_model_drift()
        self.assertIn("score_distribution", drift)

    def test_http_payload_inspection(self):
        http = inspect_http_payload_backend("http://192.168.1.100/login.php", "POST", None, "username=' UNION SELECT 1,2,3--")
        self.assertGreater(http["score"], 70)
        self.assertTrue(any("SQL Injection" in a["category"] for a in http["attacks"]))

    def test_api_monitor_syscalls(self):
        func = monitor_system_call_backend("VirtualAlloc", "cmd.exe")
        self.assertGreater(func["score"], 70)
        self.assertTrue(any("VirtualAlloc" in e["api"] for e in func["events"]))

    def test_behavior_analyzer(self):
        beh = analyze_process_behavior_backend([{"severity": "Critical"}])
        self.assertEqual(beh["risk_level"], "High Risk")
        self.assertGreater(beh["anomaly_score"], 50)

    def test_url_api_endpoints(self):
        res = handle_api_request("/dashboard/url-threats", "GET")
        self.assertEqual(res["status_code"], 200)

        url_res = handle_api_request("/scan/url", "POST", {"url": "http://secure-paypal-login.xyz"})
        self.assertEqual(url_res["status_code"], 200)
        self.assertEqual(url_res["blacklist"]["score"], 100)

        extract_res = handle_api_request("/url/extract", "POST", {"url": "http://example.com/test"})
        self.assertEqual(extract_res["status_code"], 200)
        self.assertIn("extracted_event", extract_res)

if __name__ == "__main__":
    unittest.main()

