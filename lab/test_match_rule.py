#!/usr/bin/env python3
"""Regression tests for match_rule.py.

This file exists because the same defect has now appeared twice: a modifier the
matcher does not understand falling through to exact string equality, which
reports NO_MATCH for a rule that actually works. First time it was `re`,
`base64` and `cidr`. Second time it was the chained form `|contains|all` used
across the audit_logs folder by SigmaHQ PR #5993, where splitting on the first
pipe leaves the modifier as the literal string "contains|all".

A wrong NO is worse than an honest INDETERMINATE: it gets a working rule
declared dead and deleted.

Run:  py test_match_rule.py
"""
import unittest

from match_rule import as_text, check_field, evaluate


# Shape taken verbatim from a real Entra audit event captured 2026-08-29.
# Note `newValue` is a JSON-encoded string: the quotes are part of the value,
# and the boolean is capitalised. It is never a bare lowercase JSON boolean.
CONSENT_EVENT = {
    "activityDisplayName": "Consent to application",
    "category": "ApplicationManagement",
    "result": "success",
    "targetResources": [
        {
            "type": "ServicePrincipal",
            "modifiedProperties": [
                {"displayName": "ConsentContext.IsAdminConsent", "newValue": '"True"'},
                {"displayName": "ConsentContext.IsAppOnly", "newValue": '"False"'},
                {"displayName": "ConsentContext.OnBehalfOfAll", "newValue": '"True"'},
            ],
        }
    ],
}


class ChainedModifiers(unittest.TestCase):
    def test_contains_all_matches_when_every_value_present(self):
        r = check_field(
            CONSENT_EVENT,
            "properties.targetResources|contains|all",
            ["ConsentContext.IsAdminConsent", "True"],
        )
        self.assertEqual(r["status"], "MATCH")

    def test_contains_all_fails_when_one_value_missing(self):
        """`all` must mean all. If it degraded to `any` this would wrongly pass."""
        r = check_field(
            CONSENT_EVENT,
            "properties.targetResources|contains|all",
            ["ConsentContext.IsAdminConsent", "ThisStringIsNotInTheEvent"],
        )
        self.assertEqual(r["status"], "NO_MATCH")

    def test_contains_all_does_not_fall_through_to_exact_equality(self):
        """The original bug. Exact equality against a serialized array never
        matches, so a working rule was reported dead."""
        r = check_field(
            CONSENT_EVENT, "properties.targetResources|contains|all", ["IsAdminConsent"]
        )
        self.assertNotEqual(r["status"], "NO_MATCH")
        self.assertEqual(r["status"], "MATCH")

    def test_unknown_chain_is_flagged_not_assumed(self):
        r = check_field(
            CONSENT_EVENT, "properties.targetResources|contains|startswith", ["x"]
        )
        self.assertEqual(r["status"], "UNSUPPORTED")

    def test_previously_fixed_modifiers_still_unsupported(self):
        for mod in ("re", "base64", "cidr", "gt"):
            with self.subTest(mod=mod):
                r = check_field(CONSENT_EVENT, f"category|{mod}", ["x"])
                self.assertEqual(r["status"], "UNSUPPORTED")


class Serialization(unittest.TestCase):
    def test_containers_serialize_as_json_not_python_repr(self):
        """Python repr uses single quotes, which silently changes what a
        substring test means against real log data."""
        out = as_text([{"a": "b"}])
        self.assertIn('"a"', out)
        self.assertNotIn("'a'", out)

    def test_plain_values_unchanged(self):
        self.assertEqual(as_text("Consent to application"), "Consent to application")


class FlatFieldThatDoesNotExist(unittest.TestCase):
    def test_flat_consent_field_is_not_a_key_in_the_event(self):
        """`ConsentContext.IsAdminConsent` is a displayName *value* inside an
        array, never a field. The merged SigmaHQ rule selects on it as if it
        were a field, so it has nothing to bind to."""
        keys = set()

        def walk(n):
            if isinstance(n, dict):
                for k, v in n.items():
                    keys.add(k)
                    walk(v)
            elif isinstance(n, list):
                for i in n:
                    walk(i)

        walk(CONSENT_EVENT)
        self.assertFalse([k for k in keys if "ConsentContext" in k])

    def test_matcher_says_indeterminate_not_no(self):
        """Refusing to answer is the correct behaviour for an unknown field."""
        rule = {
            "detection": {
                "selection": {"ConsentContext.IsAdminConsent": "true"},
                "condition": "selection",
            }
        }
        verdict, _, _ = evaluate(rule, CONSENT_EVENT)
        self.assertEqual(verdict, "INDETERMINATE")


class EventHubFormRule(unittest.TestCase):
    def test_rule_in_event_hub_form_fires_on_the_real_event(self):
        rule = {
            "detection": {
                "selection": {
                    "operationName": "Consent to application",
                    "properties.targetResources|contains|all": [
                        "ConsentContext.IsAdminConsent",
                        "True",
                    ],
                },
                "condition": "selection",
            }
        }
        verdict, _, _ = evaluate(rule, CONSENT_EVENT)
        self.assertEqual(verdict, "FIRES")


if __name__ == "__main__":
    unittest.main(verbosity=2)
