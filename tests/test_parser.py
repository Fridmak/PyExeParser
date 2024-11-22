import pytest
from parsers.exe_parser import EXEParser
from infrastructure.constants import ROOT_DIR


class TestParsing:
    """Tests parsers using pytest"""

    @pytest.fixture
    def calc_parser(self):
        parser = EXEParser(ROOT_DIR / 'exe_files' / 'calc.exe')
        parser.parse()
        return parser

    @pytest.fixture
    def notepad_parser(self):
        parser = EXEParser(ROOT_DIR / 'exe_files' / 'notepad.exe')
        parser.parse()
        return parser

    def test_calc_sections(self, calc_parser):
        assert len(calc_parser.header_parser.sections) == 6, "Wrong number of sections"

    def test_calc_imports(self, calc_parser):
        assert len(calc_parser.header_parser.imports) == 7, "Wrong number of imports"

    def test_notepad_sections(self, notepad_parser):
        assert len(notepad_parser.header_parser.sections) == 7, "Wrong number of sections"

    def test_notepad_imports(self, notepad_parser):
        assert len(notepad_parser.header_parser.imports) == 28, "Wrong number of imports"

    @pytest.mark.parametrize("exe_file,expected_sections,expected_imports", [
        ('calc.exe', 6, 7),
        ('notepad.exe', 7, 28),
    ])
    def test_exe_parsing(self, exe_file, expected_sections, expected_imports):
        parser = EXEParser(ROOT_DIR / 'exe_files' / exe_file)
        parser.parse()

        assert len(parser.header_parser.sections) == expected_sections, \
            f"Wrong number of sections for {exe_file}"
        assert len(parser.header_parser.imports) == expected_imports, \
            f"Wrong number of imports for {exe_file}"