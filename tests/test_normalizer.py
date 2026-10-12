import unittest

from app.normalizer import normalize_alert, get_severity_label


class TestNormalizer(unittest.TestCase):

    def test_severity_labels(self):
        """Verify Wazuh severity levels are categorized correctly."""
        self.assertEqual(get_severity_label(3), "Low")
        self.assertEqual(get_severity_label(7), "Medium")
        self.assertEqual(get_severity_label(12), "High")
        self.assertEqual(get_severity_label(15), "Critical")

    def test_file_integrity_alert(self):
        """Verify a file integrity alert is normalized correctly."""
        event = {
            "document_id": "test-001",
            "alert": {
                "@timestamp": "2026-10-08T16:57:36.956Z",
                "agent": {
                    "name": "test-server",
                    "ip": "192.0.2.10"
                },
                "rule": {
                    "level": 7,
                    "id": "550",
                    "description": "Integrity checksum changed.",
                    "mitre": {
                        "id": ["T1565.001"]
                    }
                },
                "syscheck": {
                    "path": "/etc/example/test.conf",
                    "event": "modified",
                    "changed_attributes": ["mtime", "sha256"],
                    "audit": {
                        "process": {
                            "name": "/usr/bin/perl"
                        }
                    }
                }
            }
        }

        result = normalize_alert(event)

        self.assertEqual(result["event_id"], "test-001")
        self.assertEqual(result["hostname"], "test-server")
        self.assertEqual(result["severity"], 7)
        self.assertEqual(result["severity_label"], "Medium")
        self.assertEqual(result["rule_id"], "550")
        self.assertEqual(result["mitre_ids"], ["T1565.001"])
        self.assertEqual(result["event_type"], "file_integrity")

        self.assertEqual(
            result["details"]["file_path"],
            "/etc/example/test.conf"
        )

        self.assertEqual(
            result["details"]["process"],
            "/usr/bin/perl"
        )

    def test_missing_optional_fields(self):
        """Verify alerts with missing optional fields do not crash."""
        event = {
            "document_id": "test-002",
            "alert": {
                "agent": {
                    "name": "linux-server"
                },
                "rule": {
                    "level": 3
                }
            }
        }

        result = normalize_alert(event)

        self.assertEqual(result["hostname"], "linux-server")
        self.assertEqual(result["severity"], 3)
        self.assertEqual(result["severity_label"], "Low")
        self.assertEqual(result["mitre_ids"], [])
        self.assertIsNone(result["event_type"])


if __name__ == "__main__":
    unittest.main()