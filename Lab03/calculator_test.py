import unittest
from calculator import Calculator
import math


class ApplicationTest(unittest.TestCase):
    def test_add(self):
        test_array = [
            (0, 1, 1),
            (-5, 9, 4),
            (0, 0, 0),
            (-5, 3, -2),
            (100, 999, 1099),
        ]

        for input1, input2, answer in test_array:
            result = Calculator.add(input1, input2)
            self.assertEqual(result, answer)

        with self.assertRaises(TypeError):
            Calculator.add("abc", True)

    def test_divide(self):
        test_array = [
            (4, 2, 2.0),
            (-10, 2, -5.0),
            (0, 5, 0),
            (5, 2, 2.5),
            (999, 333, 3.0),
        ]

        for input1, input2, answer in test_array:
            result = Calculator.divide(input1, input2)
            self.assertEqual(result, answer)

        with self.assertRaises(TypeError):
            Calculator.divide("abc", True)

    def test_sqrt(self):
        test_array = [
            (4, 2),
            (0, 0),
            (16, 4),
            (9, 3),
            (25, 5),
        ]

        for input, answer in test_array:
            result = Calculator.sqrt(input)
            self.assertEqual(result, answer)

        with self.assertRaises(TypeError):
            Calculator.sqrt("abc", True)

    def test_exp(self):
        E_SQUARE = round(math.e ** 2, 14)
        test_array = [
            (0, 1),
            (1, math.e),
            (-1, 1 / math.e),
            (2, E_SQUARE),
            (-2, 1 / E_SQUARE),
        ]

        for input, answer in test_array:
            result = Calculator.exp(
                input,
            )
            self.assertEqual(result, answer)

        with self.assertRaises(TypeError):
            Calculator.exp("abc")


if __name__ == "__main__":
    unittest.main()
