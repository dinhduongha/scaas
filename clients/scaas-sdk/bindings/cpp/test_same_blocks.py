# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""same_blocks.py on the generator's shapes (review T26 C-4). Run: python3 -I test_same_blocks.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from same_blocks import same

A = "struct A {\n    int x;\n    int y;\n};\n"
B = "struct B {\n    bool z;\n};\n"


class Same(unittest.TestCase):
    def test_blocks_in_another_order(self):
        self.assertTrue(same(A + "\n" + B, B + "\n" + A))

    def test_lines_in_another_order_inside_a_block(self):
        # a record's fields swapped: its converter reads them in another order, a change the check must show
        swapped = "struct A {\n    int y;\n    int x;\n};\n"
        self.assertFalse(same(A + "\n" + B, swapped + "\n" + B))

    def test_a_line_more_or_less(self):
        self.assertFalse(same(A + "\n" + B, A + "\n" + B + "\nstruct C;\n"))
        self.assertTrue(same(A + "\n" + B, A + "\n" + B), "control: the same text")


if __name__ == "__main__":
    unittest.main()
