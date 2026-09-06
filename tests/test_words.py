import re, unittest
from doorman import words


class FixedRand:
    def __init__(self, values): self.values = list(values)
    def randbelow(self, n): return self.values.pop(0) % n


class WordsTest(unittest.TestCase):
    def test_list_is_256_unique_simple_words(self):
        self.assertEqual(len(words.WORDS), 256)
        self.assertEqual(len(set(words.WORDS)), 256)
        for w in words.WORDS:
            self.assertRegex(w, r"^[a-z]{3,9}$")

    def test_code_shape(self):
        code = words.new_code()
        self.assertRegex(code, r"^[a-z]+-[a-z]+-[a-z]+-\d{2}$")

    def test_code_is_deterministic_given_the_random_source(self):
        self.assertEqual(words.new_code(FixedRand([0, 1, 2, 7])), f"{words.WORDS[0]}-{words.WORDS[1]}-{words.WORDS[2]}-07")

    def test_normalize_forgives_spaces_and_case(self):
        self.assertEqual(words.normalize("  Coral Lounger 42 "), "coral-lounger-42")
        self.assertEqual(words.normalize("coral--lounger-42"), "coral-lounger-42")
