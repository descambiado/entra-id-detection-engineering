#!/usr/bin/env python3
"""Regression tests for the audit tools.

Every false positive episode this suite produced is encoded here as a test. The
tools decide what counts as a finding, and until now none of that logic was
tested, which is how four separate runs produced large wrong numbers before
someone checked them by hand.

A trap that is only written down in a README comes back. A trap with a failing
test does not.

Run:  py test_auditors.py
"""
import json
import pathlib
import unittest

import audit_operations as ops
import audit_rules as rules
import audit_activitylogs as act
import infer_tables as inf
import audit_signinlogs as sig

HERE = pathlib.Path(__file__).parent


class Trap1_ProjectConvention(unittest.TestCase):
    """properties.message resolves to no column and 23 of 45 rules use it.

    Counting it as a defect turned 8 real candidates into 27. It is how the
    project writes this logsource, and one rule using it was merged after
    maintainer review.
    """

    def test_properties_message_is_excluded_by_name(self):
        # The exclusion belongs to audit_rules, which checks FIELD names.
        # audit_operations checks the VALUES behind an operation-name field, so
        # properties.message is an input there rather than something to skip.
        # Writing this test the other way round is how the distinction got
        # noticed, so it is spelled out here.
        self.assertIn("properties.message", rules.CONVENTIONS)

    def test_the_two_auditors_treat_it_differently_on_purpose(self):
        self.assertIn("properties.message", rules.CONVENTIONS)
        self.assertIn("properties.message", {f.lower() for f in ops.OP_FIELDS})

    def test_the_reason_is_written_down_where_someone_will_read_it(self):
        src = (HERE / "audit_rules.py").read_text(encoding="utf-8")
        self.assertIn("convention", src.lower())


class Trap2_WrongCatalogue(unittest.TestCase):
    """Checking activitylogs rules against the Entra audit list gave 128 wrong
    results. Azure Activity operations are ARM operations and live in a
    different catalogue entirely."""

    def test_arm_operation_is_absent_from_the_entra_list(self):
        self.assertNotIn("MICROSOFT.NETWORK/APPLICATIONGATEWAYS/WRITE", set(ops.MS))

    def test_and_present_in_the_arm_catalogue(self):
        self.assertIn("microsoft.network/applicationgateways/write", act.ARM_LOWER)

    def test_the_two_catalogues_do_not_overlap(self):
        entra = {m.lower() for m in ops.MS}
        arm = set(act.ARM_LOWER)
        self.assertEqual(entra & arm, set(),
                         "an operation in both catalogues means the split is wrong")


class Trap3_CaseDoesNotMatter(unittest.TestCase):
    """Six rules spell 'conditional access policy' lowercase. KQL == is case
    sensitive but the kusto backend emits =~, so these are not findings. The
    classifier must separate them from real absences so they can be ignored."""

    def test_case_only_difference_is_its_own_verdict(self):
        exact = {"Update Conditional Access policy"}
        lower = {"update conditional access policy": "Update Conditional Access policy"}
        strip = dict(zip(exact, exact))
        dash = {}
        verdict, match = ops.classify("Update conditional access policy",
                                      exact, lower, strip, dash)
        self.assertEqual(verdict, "CASE")
        self.assertEqual(match, "Update Conditional Access policy")

    def test_case_is_not_reported_as_absent(self):
        exact = {"Disable PIM alert"}
        lower = {"disable pim alert": "Disable PIM alert"}
        verdict, _ = ops.classify("Disable PIM Alert", exact, lower, dict(), dict())
        self.assertNotEqual(verdict, "ABSENT")


class Trap4_VendorListIsIncomplete(unittest.TestCase):
    """The worst one. Four rules looked broken purely because their operation
    names are absent from Microsoft's published list, then Microsoft's own
    Sentinel content turned out to query two of those exact strings.

    This is not something a unit test can prevent. What it can do is keep the
    evidence of it present, so nobody rebuilds the tool believing ABSENT means
    broken.
    """

    def test_the_known_counterexample_is_still_missing_from_the_list(self):
        self.assertNotIn("Add eligible member (permanent)", set(ops.MS))

    def test_the_docstring_says_absent_is_not_a_finding(self):
        doc = (HERE / "audit_operations.py").read_text(encoding="utf-8")
        self.assertIn("ABSENT IS A CANDIDATE, NOT A FINDING", doc)

    def test_the_arm_auditor_says_the_same(self):
        doc = (HERE / "audit_activitylogs.py").read_text(encoding="utf-8")
        self.assertIn("not a finding", doc.lower())


class Fragments(unittest.TestCase):
    """A value behind |contains is a fragment by design. Counting fragments as
    absent operation names would flag every partial-match rule in the corpus."""

    def test_arm_auditor_skips_values_with_modifiers(self):
        src = (HERE / "audit_activitylogs.py").read_text(encoding="utf-8")
        self.assertIn('counts["FRAGMENT"]', src)


class TableInference(unittest.TestCase):
    """The service to table mapping is derived, not assumed. base_of has to
    strip the properties. prefix or every Event Hub style field misses."""

    def test_properties_prefix_is_stripped(self):
        self.assertEqual(inf.base_of("properties.targetResources|contains"), "targetResources")

    def test_modifiers_are_stripped(self):
        self.assertEqual(inf.base_of("OperationName|startswith"), "OperationName")

    def test_nested_path_reduces_to_its_root(self):
        self.assertEqual(inf.base_of("DeviceDetail.trusttype"), "DeviceDetail")


class SigninLogsAuditor(unittest.TestCase):
    """The signinlogs auditor checks field names, not operation names, because
    these rules select on result codes instead."""

    def test_convention_check_sees_the_name_as_written(self):
        """A bug this tool shipped with for one run: the properties. prefix was
        stripped before the CONVENTIONS lookup, so properties.message arrived as
        'message', missed the exclusion and reported ABSENT. The tool was
        contradicting its own docstring."""
        root, written = sig.root_of("properties.message")
        self.assertEqual(written, "properties.message")
        self.assertIn(written, sig.CONVENTIONS)

    def test_root_is_still_extracted_for_the_column_lookup(self):
        root, _ = sig.root_of("properties.deviceDetail.deviceId|expand")
        self.assertEqual(root, "deviceDetail")

    def test_event_hub_envelope_names_are_conventions_not_defects(self):
        """One rule uses callerIpAddress, location, resultType and
        properties.deviceDetail.deviceId together. That is the Event Hub
        envelope used consistently, not four mistakes."""
        self.assertIn("callerIpAddress", sig.CONVENTIONS)

    def test_the_signinlogs_schema_is_the_one_being_checked_against(self):
        self.assertGreater(len(sig.COLS), 50)
        self.assertIn("ResultType", sig.COLS)
        self.assertNotIn("Username", sig.COLS)


class ReferenceData(unittest.TestCase):
    """The catalogues are the tools' ground truth. If one silently empties or
    shrinks, every verdict flips to ABSENT and the report looks like a jackpot."""

    def test_entra_catalogue_is_populated(self):
        self.assertGreater(len(ops.MS), 800, "Entra activity list looks truncated")

    def test_arm_catalogue_is_populated(self):
        self.assertGreater(len(act.ARM), 1500, "ARM operation list looks truncated")

    def test_schema_export_covers_the_tables_the_audit_needs(self):
        schema = json.loads((HERE / "azure_schema.json").read_text(encoding="utf-8"))
        for table in ("AuditLogs", "SigninLogs", "AzureActivity"):
            self.assertIn(table, schema)


if __name__ == "__main__":
    unittest.main(verbosity=2)
