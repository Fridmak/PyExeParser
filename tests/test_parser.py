from parsers.exe_parser import EXEParser
from infrastructure.constants import ROOT_DIR
import unittest

class TestParsing(unittest.TestCase):
    """Tests parsers using unittest"""

    def test_calc(self):
        parser = EXEParser(str(ROOT_DIR / 'exe_files' / 'calc.exe'))
        parser.parse()
        self.assertIs(len(parser.header_parser.sections), 6, "Wrong number of sections")
        self.assertIs(len(parser.header_parser.imports), 7, "Wrong number of imports")

    def test_notepad(self):
        parser = EXEParser(str(ROOT_DIR / 'exe_files' / 'notepad.exe'))
        parser.parse()
        self.assertIs(len(parser.header_parser.sections), 7, "Wrong number of sections")
        self.assertIs(len(parser.header_parser.imports), 28, "Wrong number of imports")


tester = TestParsing()
tester.test_calc()
tester.test_notepad()