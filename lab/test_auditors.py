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
import sanitize as san

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


class Trap6_MultipleOperationsInOneValue(unittest.TestCase):
    """Two real operation names joined into one string match nothing.

    SigmaHQ azure_app_credential_added.yml carried
    'Update Service principal/Update Application' as an exact match value from
    2022 until at least 2026-09-13. Live telemetry: the joined string 0 rows,
    'Update service principal' 6 rows, 'Update application' 3 rows.

    Our own merged PR #6247 touched the line directly above it and did not
    notice, which is why this is a test and not a note.
    """

    def setUp(self):
        self.ms_lower = {m.lower(): m for m in ops.MS}

    def test_slash_joined_pair_is_detected(self):
        parts = ops.shorthand_parts("Update Service principal/Update Application", self.ms_lower)
        self.assertEqual(parts, ["Update service principal", "Update application"])

    def test_it_gets_its_own_verdict_not_absent(self):
        verdict, _ = ops.classify(
            "Update Service principal/Update Application",
            set(ops.MS), self.ms_lower, {m.strip(): m for m in ops.MS}, {},
        )
        self.assertEqual(verdict, "SHORTHAND")

    def test_a_real_name_containing_a_slash_is_not_flagged(self):
        # 'Update member in PIM approved by admin (extend/renew)' is genuine.
        real = "Update member in PIM approved by admin (extend/renew)"
        self.assertIn(real, ops.MS)
        self.assertIsNone(ops.shorthand_parts(real, self.ms_lower))

    def test_an_ordinary_absent_string_is_not_flagged(self):
        self.assertIsNone(ops.shorthand_parts("Some/Invented Thing", self.ms_lower))

    def test_shared_prefix_form_is_detected(self):
        """'Request Approved/Denied' means two operations that share a first word.
        On SigmaHQ master until at least 2026-09-13. fukusuket's #5993 splits it
        into two values, which is the fix this verdict is meant to prompt."""
        parts = ops.shorthand_parts("Request Approved/Denied", self.ms_lower)
        self.assertEqual(parts, ["Request approved", "Request denied"])

    def test_shared_prefix_needs_every_tail_to_resolve(self):
        self.assertIsNone(ops.shorthand_parts("Request Approved/Nonsense", self.ms_lower))

    def test_shared_prefix_does_not_fire_on_an_unknown_head(self):
        self.assertIsNone(ops.shorthand_parts("Invented Thing/Denied", self.ms_lower))


class Trap7_PhraseWordOrder(unittest.TestCase):
    """A phrase can be absent while all of its words are present, reversed.

    SigmaHQ azure_user_password_change.yml selects
    `operationName|contains: 'Password reset'`, but Entra names every completed
    password operation verb first. Microsoft's own MultiplePasswordresetsbyUser
    matches tokens in any order rather than the phrase, for this exact reason.
    """

    def setUp(self):
        self.ms_lower = {m.lower(): m for m in ops.MS}

    def test_the_reversed_forms_are_offered(self):
        alts = ops.reordered_candidates("Password reset", self.ms_lower)
        self.assertIn("Reset password (self-service)", alts)
        self.assertIn("Reset password (by admin)", alts)

    def test_the_phrase_never_appears_with_the_rules_capitalisation(self):
        self.assertFalse(any("Password reset" in m for m in ops.MS))

    def test_the_two_operations_the_rule_means_do_not_contain_it(self):
        for real in ("Reset password (self-service)", "Change password (self-service)"):
            self.assertIn(real, ops.MS)
            self.assertNotIn("password reset", real.lower())

    def test_the_suggested_replacement_is_exact(self):
        hits = [m for m in ops.MS if "password (self-service)" in m.lower()]
        self.assertEqual(sorted(hits), ["Change password (self-service)",
                                        "Reset password (self-service)"])

    def test_activities_the_phrase_already_matches_are_not_suggested(self):
        """The hint is for what you missed, so anything the value already hits
        is filtered out. 'Reset password' does hit 'Reset password (by admin)',
        so that must not come back as a suggestion, while genuinely reordered
        forms like 'Admin started password reset' must."""
        alts = ops.reordered_candidates("Reset password", self.ms_lower)
        self.assertNotIn("Reset password (by admin)", alts)
        self.assertNotIn("Reset password (self-service)", alts)
        self.assertIn("Admin started password reset", alts)
        for a in alts:
            self.assertNotIn("reset password", a.lower())


class Trap8_SanitizerReportedCleanWhileLeaking(unittest.TestCase):
    """The redaction said "no leaks" while still publishing an internal id.

    2026-09-13. A captured event was prepared for a public comment. GUIDs were
    substituted before the longer string containing one of them, so
    Directory_<guid>_SHARD7_1234567 kept its shard and sequence, and the check
    passed because it only searched for the full original strings. Two separate
    mistakes, one in the substitution order and one in the verification.
    """

    def test_longest_key_is_replaced_first(self):
        m = {"abc": "SHORT", "abcdef": "LONG"}
        self.assertEqual(san.apply_map("abcdef", m), "LONG")

    def test_record_id_keeps_no_shard_or_sequence(self):
        rec = {"Id": "Directory_" + "0" * 8 + "-1111-2222-3333-444444444444" + "_SHARD7_1234567"}
        out = san.sanitize(rec)
        self.assertNotIn("SHARD7", out)
        self.assertNotIn("8791423", out)
        self.assertEqual(san.leaks(out), [])

    def test_verification_catches_an_identifier_nobody_listed(self):
        """The point of checking a shape rather than a list of known values."""
        self.assertTrue(san.leaks('{"x": "7f3a91bc-2d44-4e11-9a8c-5b6d0e2f7a13"}'))
        self.assertTrue(san.leaks('{"ip": "198.51.100.7"}'))
        self.assertTrue(san.leaks('{"upn": "someone_gmail.com#EXT#@tenant.onmicrosoft.com"}'))

    def test_placeholders_are_not_reported_as_leaks(self):
        clean = '{"g": "11111111-1111-1111-1111-111111111111", "ip": "203.0.113.10"}'
        self.assertEqual(san.leaks(clean), [])

    def test_the_evidence_itself_survives(self):
        """The dash findings rest on U+2013 and a trailing space. If redaction
        normalised either of them the sample would prove the opposite."""
        op = "Update application – Certificates and secrets management "
        out = san.sanitize({"OperationName": op})
        self.assertIn("–", out)
        self.assertIn('management "', out)

    def test_names_are_redacted_inside_embedded_json(self):
        """Log Analytics returns TargetResources as a string holding JSON."""
        rec = {"TargetResources": '[{"displayName": "app-registration-7", "type": "ServicePrincipal"}]'}
        out = san.sanitize(rec)
        self.assertNotIn("DELETE-ME", out)
        self.assertIn("ServicePrincipal", out)

    def test_same_input_gives_same_output(self):
        rec = {"a": "7f3a91bc-2d44-4e11-9a8c-5b6d0e2f7a13", "b": "10.1.2.3"}
        self.assertEqual(san.sanitize(rec), san.sanitize(rec))

    def test_user_agent_is_redacted(self):
        """It carries the operating system build, which fingerprints the machine.
        Missed by the first two passes of this module and found by an
        independent sweep that looked for known real values instead of shapes."""
        rec = {"AdditionalDetails": '[{"key": "User-Agent", "value": "python/9.9.9 (Windows-99-0.0.00000-SP0) AZURECLI/9.9.9"}]'}
        out = san.sanitize(rec)
        self.assertNotIn("Windows-99", out)
        self.assertNotIn("AZURECLI", out)
        self.assertIn("User-Agent", out)

    def test_name_inside_a_credential_blob_is_redacted(self):
        """KeyDescription splices the credential name into a flat string, so no
        walk over JSON keys ever reaches it."""
        rec = {"TargetResources": '[{"modifiedProperties": [{"displayName": "KeyDescription", "newValue": "[\"[KeyIdentifier=7f3a91bc-2d44-4e11-9a8c-5b6d0e2f7a13,KeyType=Password,KeyUsage=Verify,DisplayName=my-app-secret]\"]"}]}]'}
        out = san.sanitize(rec)
        self.assertNotIn("my-app-secret", out)
        self.assertIn("KeyType=Password", out)   # la evidencia se queda

    def test_module_carries_no_real_identifier(self):
        """It lives in a public repo, so it must not embed anything of his.

        This test failed on its first run and was right to: the docstring still
        quoted the real shard and sequence from the record that caused the leak.
        Only the module's own vocabulary is tolerated here, the two constants it
        has to name in order to match them. Identifiers are not tolerated at all.
        """
        src = pathlib.Path(san.__file__).read_text(encoding="utf-8")
        vocabulary = {"guest-upn-marker", "record-id-shard"}
        real = [x for x in san.leaks(src) if x[0] not in vocabulary]
        self.assertEqual(real, [], "an identifier is embedded in a public file")


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
