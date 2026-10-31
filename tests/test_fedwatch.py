"""Run with: python -m unittest discover -s tests"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import fedwatch as fw  # noqa: E402

BASE = {
    "info": {"version": "1", "last_updated": "2026-01-01"},
    "FRD": {"info": {"name": "FedRAMP Definitions"}, "data": {"all": {
        "FRD-ACV": {"term": "Accepted Vulnerability", "definition": "A vulnerability the provider will not fix."}}}},
    "FRR": {"VDR": {
        "info": {"name": "Vulnerability Detection and Response", "effective": {"date": {"obtain": "2026-12-07"}}},
        "data": {"all": {"TFR": {
            "VDR-TFR-NMV": {"name": "Non-Machine Validation", "statement": "Providers SHOULD validate quarterly.",
                            "force": "SHOULD", "timeframe_type": "months", "timeframe_num": 3,
                            "controls": ["ra-5"], "updated": [{"date": "2026-06-24", "comment": "Launch"}]},
            "VDR-TFR-OLD": {"name": "Old Rule", "statement": "Providers MAY do the old thing every month without fail."}}}}}},
    "KSI": {}, "CTL": {},
}


class DiffTests(unittest.TestCase):
    def diff(self, mutate):
        new = copy.deepcopy(BASE)
        mutate(new)
        return fw.diff_docs(BASE, new)

    def test_no_change(self):
        self.assertTrue(fw.is_empty(fw.diff_docs(BASE, copy.deepcopy(BASE))))

    def test_changelog_only_is_ignored(self):
        def m(d):
            d["FRR"]["VDR"]["data"]["all"]["TFR"]["VDR-TFR-NMV"]["updated"].append({"date": "x", "comment": "y"})
        self.assertTrue(fw.is_empty(self.diff(m)))

    def test_obligation_strengthened(self):
        def m(d):
            r = d["FRR"]["VDR"]["data"]["all"]["TFR"]["VDR-TFR-NMV"]
            r["force"], r["statement"] = "MUST", "Providers MUST validate quarterly."
        x = self.diff(m)["changed"][0]
        self.assertEqual(x["grade"], "substantive")
        self.assertTrue(any("stronger" in s for s in x["sentences"]))
        self.assertTrue(any("Normative keywords" in s for s in x["sentences"]))

    def test_deadline_change(self):
        def m(d):
            d["FRR"]["VDR"]["data"]["all"]["TFR"]["VDR-TFR-NMV"]["timeframe_num"] = 1
        x = self.diff(m)["changed"][0]
        self.assertIn("Deadline changed from **3 months** to **1 month**.", x["sentences"])

    def test_mapping_only(self):
        def m(d):
            d["FRR"]["VDR"]["data"]["all"]["TFR"]["VDR-TFR-NMV"]["controls"] = ["ra-5", "si-2"]
        x = self.diff(m)["changed"][0]
        self.assertEqual(x["grade"], "mapping")

    def test_editorial(self):
        def m(d):
            d["FRD"]["data"]["all"]["FRD-ACV"]["definition"] = "A vulnerability the provider will not fix"
        self.assertEqual(self.diff(m)["changed"][0]["grade"], "editorial")

    def test_add_remove_and_reid(self):
        def m(d):
            tfr = d["FRR"]["VDR"]["data"]["all"]["TFR"]
            tfr["VDR-TFR-NEW"] = tfr.pop("VDR-TFR-OLD")
            tfr["VDR-TFR-ADD"] = {"name": "Brand New", "statement": "Providers MUST do something new."}
        d = self.diff(m)
        self.assertEqual([r["id"] for r in d["added"]], ["VDR-TFR-ADD"])
        self.assertEqual(d["removed"], [])
        self.assertEqual((d["renamed"][0]["from"], d["renamed"][0]["to"]), ("VDR-TFR-OLD", "VDR-TFR-NEW"))

    def test_effective_date(self):
        def m(d):
            d["FRR"]["VDR"]["info"]["effective"]["date"]["obtain"] = "2027-01-04"
        d = self.diff(m)
        self.assertEqual(d["meta"][0]["fields"][0]["label"], "Effective date (obtain)")
        self.assertTrue(any("2027-01-04" in s for s in fw.glance(d)))


if __name__ == "__main__":
    unittest.main()
