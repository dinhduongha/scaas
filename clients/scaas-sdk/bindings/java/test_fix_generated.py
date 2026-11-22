# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""fix_generated.py's three fixes, each on the generator's own text (plan T20e2). Run: python3 -I test_fix_generated.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fix_generated import fix


class Fix(unittest.TestCase):
    def test_tuple_variant_close(self):
        self.assertEqual(
            fix("AutoCloseableHelper.close(\n        this.);"), "AutoCloseableHelper.close(\n        this.v1);"
        )
        self.assertEqual(
            fix("AutoCloseableHelper.close(this., this.);"), "AutoCloseableHelper.close(this.v1, this.v2);"
        )
        self.assertEqual(fix("AutoCloseableHelper.close(this.words);"), "AutoCloseableHelper.close(this.words);")

    def test_value_bound_in_case(self):
        src = (
            "    public void write(EndpointAuth value, java.nio.ByteBuffer buf) {\n"
            "      switch (value) {\n"
            "        case EndpointAuth.Header(var name, var value) -> {\n"
            "          FfiConverterTypeSecret.INSTANCE.write(value, buf);\n"
            "        }\n"
            "        case EndpointAuth.Bearer(var v1) -> {\n"
            "          FfiConverterTypeSecret.INSTANCE.write(v1, buf);\n"
        )
        out = fix(src)
        self.assertIn("case EndpointAuth.Header(var name, var value_) ->", out)
        self.assertIn("INSTANCE.write(value_, buf);", out)
        self.assertIn("switch (value) {", out)
        self.assertIn("INSTANCE.write(v1, buf);", out)

    def test_value_binding_stops_at_the_arm(self):
        src = (
            "        case EndpointAuth.Header(var name, var value) -> {\n"
            "          FfiConverterTypeSecret.INSTANCE.write(value, buf);\n"
            "        }\n"
            "      }\n"
            "      FfiConverterString.INSTANCE.write(value, buf);\n"
        )
        out = fix(src)
        self.assertIn("INSTANCE.write(value_, buf);", out)
        self.assertTrue(out.endswith("FfiConverterString.INSTANCE.write(value, buf);\n"), "the method's own value kept")

    def test_class_shadowed(self):
        self.assertEqual(
            fix("        Class<?> ignored = UniffiLib.class;"), "        java.lang.Class<?> ignored = UniffiLib.class;"
        )
        self.assertEqual(fix("java.lang.Class<?> x;"), "java.lang.Class<?> x;")


if __name__ == "__main__":
    unittest.main()
