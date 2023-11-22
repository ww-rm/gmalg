import unittest

from gmalg import SM3


class TestSM3(unittest.TestCase):
    def test_case1(self):
        h = SM3()
        h.update(b"abc")
        self.assertEqual(h.value, bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"))

    def test_case2(self):
        h = SM3()
        h.update(b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
        self.assertEqual(h.value, bytes.fromhex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"))

    def test_update(self):
        h = SM3()
        h.update(b"abc")
        self.assertEqual(h.value, bytes.fromhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"))
        h.update(b"dabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
        self.assertEqual(h.value, bytes.fromhex("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"))


if __name__ == "__main__":
    unittest.main()
