#!/usr/bin/env python3
"""
Unit tests for PRODIGY_CS_03 Password Complexity Checker.
"""

import unittest
from password_checker import PasswordChecker

class TestPasswordChecker(unittest.TestCase):

    def test_weak_passwords(self):
        result = PasswordChecker.evaluate("123456")
        self.assertEqual(result["rating"], "Very Weak")
        self.assertTrue(result["is_common"])

        result_short = PasswordChecker.evaluate("abc")
        self.assertEqual(result_short["rating"], "Very Weak")

    def test_moderate_password(self):
        result = PasswordChecker.evaluate("Pass1234")
        self.assertIn(result["rating"], ["Weak", "Moderate"])
        self.assertTrue(result["has_upper"])
        self.assertTrue(result["has_lower"])
        self.assertTrue(result["has_digit"])

    def test_strong_password(self):
        result = PasswordChecker.evaluate("K9#mP$9vL2!xQ18#")
        self.assertEqual(result["rating"], "Very Strong")
        self.assertTrue(result["has_upper"])
        self.assertTrue(result["has_lower"])
        self.assertTrue(result["has_digit"])
        self.assertTrue(result["has_special"])
        self.assertGreater(result["entropy"], 80)

    def test_entropy_calculation(self):
        entropy_empty = PasswordChecker.calculate_entropy("")
        self.assertEqual(entropy_empty, 0.0)

        # 8 lowercase letters: 8 * log2(26) = 37.6
        entropy_lower = PasswordChecker.calculate_entropy("abcdefgh")
        self.assertAlmostEqual(round(entropy_lower, 1), 37.6)

    def test_generator(self):
        pwd = PasswordChecker.generate_secure_password(16)
        self.assertEqual(len(pwd), 16)
        eval_res = PasswordChecker.evaluate(pwd)
        self.assertEqual(eval_res["rating"], "Very Strong")

if __name__ == "__main__":
    unittest.main()
