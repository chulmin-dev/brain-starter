"""Wave 2 ADAPT-2 + Wave 3 M3 — engine honors url_transform_first hint.

Pins:
  - When user_hint carries url_transform_first and that transform exists in
    the profile's url_transform_order, it is moved to position 0.
  - Other transforms are kept (just reordered) so cold-start fallback is intact.
  - When url_transform_first is absent from the hint, transform_order is unchanged.
  - When url_transform_first names a transform NOT in the profile's order, the
    order is unchanged (no injection of unknown transforms).
  - The hint is read from user_hint dict; no fetch() signature change needed.

M3 (Wave 3): the promotion logic is now in the pure helper
`engine.fetch_chain._promote_transform_first()`. Tests call the REAL
production function — the previous hand-copied `_apply_adapt2` duplicate
was anti-slop and is removed.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILL_ROOT))

from engine.fetch_chain import _promote_transform_first


class Adapt2TransformFrontTest(unittest.TestCase):
    """ADAPT-2: url_transform_first grid-front promotion (calls real helper)."""

    def test_known_transform_moves_to_front(self):
        order = ["original", "mobile_subdomain", "amp"]
        hint  = {"url_transform_first": "mobile_subdomain"}
        result = _promote_transform_first(order, hint)
        self.assertEqual(result[0], "mobile_subdomain")

    def test_all_other_transforms_preserved(self):
        order = ["original", "mobile_subdomain", "amp"]
        hint  = {"url_transform_first": "mobile_subdomain"}
        result = _promote_transform_first(order, hint)
        self.assertIn("original", result)
        self.assertIn("amp", result)
        self.assertEqual(len(result), 3)

    def test_no_duplicate_after_promotion(self):
        """The promoted transform must appear exactly once."""
        order = ["original", "mobile_subdomain"]
        hint  = {"url_transform_first": "mobile_subdomain"}
        result = _promote_transform_first(order, hint)
        self.assertEqual(result.count("mobile_subdomain"), 1)

    def test_no_hint_leaves_order_unchanged(self):
        order = ["original", "mobile_subdomain"]
        result = _promote_transform_first(order, {})
        self.assertEqual(result, ["original", "mobile_subdomain"])

    def test_hint_with_unknown_transform_leaves_order_unchanged(self):
        """A hint naming a transform not in the profile must be ignored."""
        order = ["original", "amp"]
        hint  = {"url_transform_first": "nonexistent_transform"}
        result = _promote_transform_first(order, hint)
        self.assertEqual(result, ["original", "amp"])

    def test_hint_with_none_value_leaves_order_unchanged(self):
        order = ["original", "amp"]
        hint  = {"url_transform_first": None}
        result = _promote_transform_first(order, hint)
        self.assertEqual(result, ["original", "amp"])

    def test_hint_with_empty_string_leaves_order_unchanged(self):
        order = ["original", "amp"]
        hint  = {"url_transform_first": ""}
        result = _promote_transform_first(order, hint)
        self.assertEqual(result, ["original", "amp"])

    def test_already_at_front_is_no_op(self):
        """If the hinted transform is already first, order must be identical."""
        order = ["original", "amp"]
        hint  = {"url_transform_first": "original"}
        result = _promote_transform_first(order, hint)
        self.assertEqual(result, ["original", "amp"])

    def test_single_element_order(self):
        order = ["original"]
        hint  = {"url_transform_first": "original"}
        result = _promote_transform_first(order, hint)
        self.assertEqual(result, ["original"])

    def test_fetch_chain_contains_adapt2_helper(self):
        """M3: production helper _promote_transform_first must exist in fetch_chain.py."""
        fc_path = _SKILL_ROOT / "engine" / "fetch_chain.py"
        source = fc_path.read_text()
        self.assertIn("url_transform_first", source,
                      "ADAPT-2 block missing from fetch_chain.py")
        self.assertIn("_promote_transform_first", source,
                      "M3 helper _promote_transform_first missing from fetch_chain.py")
        self.assertIn("ADAPT-2", source,
                      "ADAPT-2 comment missing from fetch_chain.py")


if __name__ == "__main__":
    unittest.main()
