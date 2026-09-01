import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from modules.file_scanner.scanner import FileThreatScannerEngine
from modules.file_scanner.metadata import extract_file_metadata
from modules.file_scanner.static_analysis import perform_static_analysis, calculate_entropy
from modules.file_scanner.yara_scan import scan_yara_rules
from modules.file_scanner.signature_scan import scan_signatures
from modules.file_scanner.reputation import check_reputation
from modules.file_scanner.dynamic_analysis import run_sandbox_analysis
from api import handle_api_request

class TestFileThreatScannerBackend(unittest.TestCase):
    def setUp(self):
        self.engine = FileThreatScannerEngine()

    def test_metadata_extraction(self):
        meta = extract_file_metadata("test string content", "sample.txt")
        self.assertEqual(meta["filename"], "sample.txt")
        self.assertEqual(meta["extension"], ".txt")
        self.assertTrue(len(meta["sha256"]) == 64)

    def test_entropy_calculation(self):
        low_entropy = calculate_entropy(b"AAAAAA")
        high_entropy = calculate_entropy(bytes(range(256)))
        self.assertLess(low_entropy, 1.0)
        self.assertGreater(high_entropy, 7.0)

    def test_static_analysis(self):
        res = perform_static_analysis("<?php eval($_POST['cmd']); ?>", "webshell.php")
        self.assertIn("Code Execution Primitive", res["suspicious_apis"])

    def test_yara_scan(self):
        res = scan_yara_rules("WannaCrypt WNCRY!", "virus.exe")
        self.assertGreater(res["score"], 50)
        self.assertTrue(any(m["rule"] == "WannaCry_Ransomware" for m in res["matches"]))

    def test_full_scanner_engine_malicious(self):
        malicious_content = "WannaCrypt WNCRY! system('nc -e /bin/sh');"
        res = self.engine.scan_file(malicious_content, "WannaCry_test.exe")

        self.assertIn(res["decision"], ["QUARANTINE", "BLOCK + ALERT"])
        self.assertGreater(res["threat_score"], 60)
        self.assertIsNotNone(res["engine_breakdown"])

    def test_full_scanner_engine_clean(self):
        clean_content = '{"serverName": "SOC-Node-01", "active": true}'
        res = self.engine.scan_file(clean_content, "config.json")

        self.assertEqual(res["decision"], "ALLOW")
        self.assertLessEqual(res["threat_score"], 30)

    def test_api_endpoints(self):
        res = handle_api_request("/dashboard/file-threats", "GET")
        self.assertEqual(res["status_code"], 200)
        self.assertIn("summary", res)

        scan_res = handle_api_request("/scan/file", "POST", {"filename": "test.txt", "content": "clean data"})
        self.assertEqual(scan_res["status_code"], 200)
        self.assertEqual(scan_res["data"]["decision"], "ALLOW")

if __name__ == "__main__":
    unittest.main()
