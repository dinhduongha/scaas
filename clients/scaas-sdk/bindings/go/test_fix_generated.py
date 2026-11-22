# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""fix_generated.py's fix on the generator's own text (plan T20h). Run: python3 -I test_fix_generated.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fix_generated import fix

SRC = (
    "func LiftFromExternalTypeAllowOpaqueCall(value bool) AllowOpaqueCall {\n"
    "\treturn FfiConverterTypeAllowOpaqueCallINSTANCE.Lift(C.int8_t(value))\n"
    "}\n\n"
    "func LowerToExternalTypeAllowOpaqueCall(value AllowOpaqueCall) bool {\n"
    "\treturn bool(FfiConverterTypeAllowOpaqueCallINSTANCE.Lower(value))\n"
    "}\n"
)


class Fix(unittest.TestCase):
    def test_bool_custom_type_helpers(self):
        out = fix(SRC)
        self.assertNotIn("C.int8_t(value)", out)
        self.assertIn("if value {\n\t\t\treturn 1", out)
        self.assertIn("return FfiConverterTypeAllowOpaqueCallINSTANCE.Lower(value) != 0", out)

    def test_other_types_untouched(self):
        src = "func LiftFromExternalTypeSmall(value int8) Small {\n\treturn FfiConverterTypeSmallINSTANCE.Lift(C.int8_t(value))\n}\n"
        self.assertEqual(fix(src), src)


if __name__ == "__main__":
    unittest.main()
