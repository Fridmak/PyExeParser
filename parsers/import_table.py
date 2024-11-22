import struct
from infrastructure.import_describition import Import, ImportDescriptor
from infrastructure.section import Section
from infrastructure.errors import EXEParsingError
from infrastructure.constants import (
    IMPORT_DESCRIPTOR_SIZE, ORDINAL_FLAG_PE32,
    ORDINAL_FLAG_PE32_PLUS, ORDINAL_MASK
)


class ImportTableParser:
    """Парсер таблицы импортов в PE файлах"""

    def __init__(self, file_path: str, sections: list[Section], import_rva: int, import_size: int, is_pe32_plus: bool):
        self.file_path = file_path
        self.sections = sections
        self.import_rva = import_rva
        self.import_size = import_size
        self.is_pe32_plus = is_pe32_plus
        self.imports: list[Import] = []

    def rva_to_offset(self, rva: int) -> int:
        """Преобразует RVA в файловое смещение"""

        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + max(section.virtual_size,
                                                                              section.size_of_raw_data):
                return section.pointer_to_raw_data + (rva - section.virtual_address)
        raise EXEParsingError(f"Не удалось преобразовать RVA 0x{rva:X} в файловое смещение.")

    def parse(self) -> list[Import]:
        """Parses file and gets Imports"""

        with open(self.file_path, 'rb') as f:
            self._parse_import_descriptors(f)
        return self.imports

    def _parse_import_descriptors(self, f) -> None:
        """Gets dll_name and funcs, creates Imports"""

        current_rva = self.import_rva
        while True:
            descriptor = self._read_import_descriptor(f, current_rva)
            if descriptor is None:
                break
            dll_name = self._read_dll_name(f, descriptor.name_rva)
            functions = self._parse_thunks(f, descriptor)
            self.imports.append(Import(dll_name, functions))
            current_rva += IMPORT_DESCRIPTOR_SIZE

    def _read_import_descriptor(self, f, rva: int) -> ImportDescriptor | None:

        try:
            offset = self.rva_to_offset(rva)
            f.seek(offset)
            descriptor_data = f.read(IMPORT_DESCRIPTOR_SIZE)
            if len(descriptor_data) < IMPORT_DESCRIPTOR_SIZE:
                return None
            descriptor = struct.unpack("<IIIII", descriptor_data)
            if all(value == 0 for value in descriptor):
                return None
            return ImportDescriptor(*descriptor)
        except EXEParsingError:
            return None

    def _read_dll_name(self, f, name_rva: int) -> str:
        """Reads dll name from file"""

        try:
            name_offset = self.rva_to_offset(name_rva)
            f.seek(name_offset)
            return self._read_null_terminated_string(f)
        except EXEParsingError:
            return "Unknown"

    def _read_null_terminated_string(self, f) -> str:
        """Gets decoded name from f"""

        result = []
        while True:
            char = f.read(1)
            if not char or char == b'\x00':
                break
            result.append(char)
        return b''.join(result).decode('utf-8', errors='replace')

    def _parse_thunks(self, f, descriptor: ImportDescriptor) -> list[str]:
        """Gets all functions"""

        functions = []
        thunk_rva = descriptor.original_first_thunk if descriptor.original_first_thunk != 0 else descriptor.first_thunk
        while True:
            func_name = self._read_thunk(f, thunk_rva)
            if func_name is None:
                break
            functions.append(func_name)
            thunk_rva += 8 if self.is_pe32_plus else 4
        return functions

    def _read_thunk(self, f, thunk_rva: int) -> [str | None]:
        """Reads func's name"""

        try:
            offset = self.rva_to_offset(thunk_rva)
            f.seek(offset)
            thunk_data = f.read(8 if self.is_pe32_plus else 4)
            if not thunk_data or len(thunk_data) < (8 if self.is_pe32_plus else 4):
                return None

            func_rva = self._extract_func_rva(thunk_data)
            if func_rva == 0:
                return None
            if self._is_ordinal(func_rva):
                return f"Ordinal_{func_rva & ORDINAL_MASK}"
            return self._read_imported_function_name(f, func_rva)
        except EXEParsingError:
            return None

    def _extract_func_rva(self, thunk_data: bytes) -> int:
        """Gets func's RVA"""

        if self.is_pe32_plus:
            func_rva_low, func_rva_high = struct.unpack("<II", thunk_data)
            return (func_rva_high << 32) | func_rva_low
        return struct.unpack("<I", thunk_data)[0]

    def _is_ordinal(self, func_rva: int) -> bool:
        return bool(func_rva & (ORDINAL_FLAG_PE32_PLUS if self.is_pe32_plus else ORDINAL_FLAG_PE32))

    def _read_imported_function_name(self, f, func_rva: int) -> str:
        """Reads name of imported function"""

        try:
            name_offset = self.rva_to_offset(func_rva)
            f.seek(name_offset + 2)  # Пропускаем Hint (2 байта)
            return self._read_null_terminated_string(f)
        except EXEParsingError:
            return "Unknown"
