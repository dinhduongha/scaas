# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""fix_generated.py's fix on the generator's own text (plan T20d). Run: python3 -I test_fix_generated.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fix_generated import fix


class Fix(unittest.TestCase):
    def test_cancel_from_a_foreign_thread(self):
        src = "    (eventloop, task) = _UNIFFI_FOREIGN_FUTURE_HANDLE_MAP.remove(handle)\n    eventloop.call_soon(_uniffi_cancel_task, task)\n"
        out = fix(src)
        self.assertIn("eventloop.call_soon_threadsafe(_uniffi_cancel_task, task)", out)
        self.assertNotIn("eventloop.call_soon(", out)

    def test_other_calls_untouched(self):
        src = "eventloop.call_soon(other)\n"
        self.assertEqual(fix(src), src)


if __name__ == "__main__":
    unittest.main()
