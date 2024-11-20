from infrastructure.header_parser import BaseHeaderParser, Import
from infrastructure.errors import EXEParsingError
import struct
from infrastructure.constants import (
    MZ_HEADER_SIZE, WORD_SIZE, PE_SIGNATURE,
    E_LFANEW_OFFSET, MZ_SIGNATURE, DWORD_SIZE
)
from typing import BinaryIO, List
from .pe_parser import PEHeaderParser

class MZHeaderParser(BaseHeaderParser):
    """Парсер для MZ (DOS) заголовков EXE файлов."""

    def parse(self):
        """Обертка парсинга MZ заголовка"""

        try:
            with open(self.file_path, 'rb') as f:
                self.handle_exe_file(f)
        except EXEParsingError:
            self.sections = []
            self.imports = []
            raise

    def handle_exe_file(self, f: BinaryIO) -> None:
        """Парсинг MZ заголовка"""

        mz_header = f.read(MZ_HEADER_SIZE)
        self.check_mz_header(mz_header)

        e_magic = mz_header[:WORD_SIZE]
        self.check_e_magic(e_magic)

        e_lfanew = struct.unpack("<I", mz_header[E_LFANEW_OFFSET:E_LFANEW_OFFSET + DWORD_SIZE])[0]
        self.move_to_pe_header(f, pe_offset=e_lfanew)

    def move_to_pe_header(self, f, pe_offset) -> None:
        """Чтение PE заголовка и его обработка"""

        f.seek(pe_offset)
        pe_signature = f.read(len(PE_SIGNATURE))
        if pe_signature == PE_SIGNATURE:
            pe_parser = PEHeaderParser(self.file_path, pe_offset)
            pe_parser.parse()
            self.sections = pe_parser.sections
            self.imports = pe_parser.get_imports()
        else:
            self.sections, self.imports = [], []

    def check_e_magic(self, e_magic: bytes) -> None:
        if e_magic != MZ_SIGNATURE:
            raise EXEParsingError("Неверный MZ заголовок.")

    def check_mz_header(self, mz_header: bytes) -> None:
        if len(mz_header) < MZ_HEADER_SIZE:
            raise EXEParsingError("Недостаточно данных для MZ заголовка.")

    def get_imports(self) -> List[Import]:
        return self.imports