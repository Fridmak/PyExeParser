from typing import BinaryIO, List, Any
import struct
from Infrastructure.logs_writer import write_log
from Infrastructure.presentations import HeaderParser, Section, Import
from Infrastructure.errors import EXEParsingError
from Infrastructure.constants import (
    PE_HEADER_SIZE, PE_SIGNATURE, PE32_MAGIC, PE32_PLUS_MAGIC,
    SECTION_HEADER_SIZE, DATA_DIRECTORY_PE32_OFFSET,
    DATA_DIRECTORY_PE32PLUS_OFFSET, NUMBER_OF_RVA_SIZES_OFFSET
)
from .import_table import ImportTableParser


class PEHeaderParser(HeaderParser):
    """Парсер для PE (Portable Executable) заголовков EXE файлов."""

    def __init__(self, file_path: str, pe_offset: int):
        super().__init__(file_path)
        self.pe_offset = pe_offset
        self.is_pe32_plus = False  # По умолчанию PE32

    def parse(self):
        try:
            with open(self.file_path, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
                self.check_pe_offset(file_size)
                f.seek(self.pe_offset)
                pe_header = f.read(PE_HEADER_SIZE)
                signature = pe_header[:len(PE_SIGNATURE)]
                self.check_signature(signature)
                (machine, number_of_sections, time_date_stamp,
                 pointer_to_symbol_table, number_of_symbols,
                 size_of_optional_header, characteristics) = struct.unpack("<HHIIIHH", pe_header[4:24])
                self.check_optional_header(size_of_optional_header, file_size)
                optional_header = f.read(size_of_optional_header)
                magic = struct.unpack("<H", optional_header[:2])[0]
                self.handle_magic(magic)
                import_directory_rva, import_directory_size = self.handle_import_dir(optional_header)
                self.check_sections_length(size_of_optional_header, number_of_sections, file_size)
                self.sections = self.read_sections(number_of_sections, f)
                self.read_sections_raw_rata(f)
                self.handle_imports(import_directory_rva, import_directory_size)

        except (struct.error, IOError) as e:
            raise EXEParsingError(f"Ошибка при чтении PE заголовка: {str(e)}")

    def handle_import_dir(self, optional_header: bytes) -> tuple[Any, ...]:
        data_directories_offset = (
            DATA_DIRECTORY_PE32PLUS_OFFSET if self.is_pe32_plus 
            else DATA_DIRECTORY_PE32_OFFSET
        )

        if len(optional_header) < data_directories_offset + 16:
            return (0, 0)
        
        number_of_rva_and_sizes = struct.unpack(
            "<I", 
            optional_header[NUMBER_OF_RVA_SIZES_OFFSET:NUMBER_OF_RVA_SIZES_OFFSET + 4]
        )[0]
        
        if number_of_rva_and_sizes < 2:
            return (0, 0)
            
        return struct.unpack(
            "<II",
            optional_header[data_directories_offset + 8:data_directories_offset + 16]
        )

    def handle_magic(self, magic: int) -> None:
        if magic == PE32_MAGIC:
            self.is_pe32_plus = False
        elif magic == PE32_PLUS_MAGIC:
            self.is_pe32_plus = True
        else:
            raise EXEParsingError("Неизвестный формат Optional заголовка PE.")

    def check_sections_length(self, header_size: int, number_of_sections: int, file_size: int) -> None:
        if self.pe_offset + 24 + header_size + number_of_sections * 40 > file_size:
            raise EXEParsingError("Недостаточно данных для секционных заголовков PE.")

    def check_optional_header(self, size_of_optional_header: int, file_size: int) -> None:
        if self.pe_offset + 24 + size_of_optional_header > file_size:
            raise EXEParsingError("Недостаточно данных для Optional заголовка PE.")

    def check_signature(self, signature: bytes) -> None:
        if signature != b'PE\x00\x00':
            raise EXEParsingError("Неверный PE заголовок.")

    def check_pe_offset(self, file_size: int) -> None:
        if self.pe_offset + 24 > file_size:
            raise EXEParsingError("Недостаточно данных для PE заголовка.")

    def read_sections(self, number_of_sections: int, f: BinaryIO) -> List[Section]:
        sections = []

        for section_num in range(number_of_sections):
            section_header = f.read(SECTION_HEADER_SIZE)
            if len(section_header) < SECTION_HEADER_SIZE:
                raise EXEParsingError("Недостаточно данных для секционного заголовка PE.")

            name = section_header[:8].rstrip(b'\x00').decode('utf-8', errors='replace')
            try:
                (virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data,
                 pointer_to_relocations, pointer_to_linenumbers,
                 number_of_relocations, number_of_linenumbers,
                 characteristics) = struct.unpack("<IIIIIIHHI", section_header[8:40])
            except struct.error as e:
                raise EXEParsingError(f"Ошибка распаковки секционного заголовка: {e}")

            write_log(f"[DEBUG] Section {section_num}: Name={name}, VA=0x{virtual_address:X}, "
                      f"RawDataOffset=0x{pointer_to_raw_data:X}, RawDataSize=0x{size_of_raw_data:X}")

            section = Section(name, virtual_address, virtual_size,
                              size_of_raw_data, pointer_to_raw_data, b'')  # raw_data будет прочитано позже
            sections.append(section)

        return sections

    def handle_imports(self, import_directory_rva: int, dir_size: int) -> None:
        if import_directory_rva == 0:
            self.imports = []
            return

        import_parser = ImportTableParser(
            self.file_path,
            self.sections,
            import_directory_rva,
            dir_size,
            self.is_pe32_plus
        )
        self.imports = import_parser.parse()

    def read_sections_raw_rata(self, f: BinaryIO) -> None:
        for section in self.sections:
            if section.size_of_raw_data == 0:
                section.raw_data = b''
                continue
            try:
                f.seek(section.pointer_to_raw_data)
                raw_data = f.read(section.size_of_raw_data)
                section.raw_data = raw_data
                write_log(f"[DEBUG] Read raw data for section {section.name}")
            except Exception as e:
                write_log(f"[WARNING] Не удалось прочитать сырые данные для секции {section.name}: {e}")
                section.raw_data = b''

    def get_imports(self) -> List[Import]:
        return self.imports
