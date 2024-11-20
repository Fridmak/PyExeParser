import os
from typing import Optional, List
from .mz_parser import MZHeaderParser
from infrastructure.errors import EXEParsingError, UnsupportedFormatError
from infrastructure.machine_code  import MachineCode
from infrastructure.section import Section
from infrastructure.import_describition import Import
from infrastructure.constants import MZ_SIGNATURE, WORD_SIZE, OUTPUT_BIN_DIR



class EXEParser:
    """Основной класс для парсинга EXE файлов (MZ, PE)."""

    def __init__(self, file_path: str):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Файл не найден: {file_path}")
        self.file_path = file_path
        self.header_parser: Optional[MZHeaderParser] = None

    def parse(self):
        """Определяет формат EXE файла и парсит его."""

        try:
            with open(self.file_path, 'rb') as f:
                mz_header = f.read(WORD_SIZE)
                if mz_header != MZ_SIGNATURE:
                    raise UnsupportedFormatError("Файл не является MZ EXE файлом.")

            if self.header_parser is None:
                self.header_parser = MZHeaderParser(self.file_path)
            self.header_parser.parse()
        except Exception as e:
            self.header_parser = None
            raise

    def get_sections(self) -> List[Section]:
        """Возвращает список секций EXE файла."""

        if not self.header_parser:
            raise EXEParsingError("Файл не был распарсен.")
        return self.header_parser.sections

    def get_imports(self) -> List[Import]:
        """Возвращает таблицу импортов EXE файла."""

        if not self.header_parser:
            raise EXEParsingError("Файл не был распарсен.")
        return self.header_parser.get_imports()

    def get_machine_code(self) -> List[MachineCode]:
        """Извлекает машинный код из всех секций .text"""

        if not self.header_parser:
            raise EXEParsingError("Файл не был распарсен.")

        text_sections = []
        for section in self.header_parser.sections:
            if section.name.lower().startswith('.text'):  # Включаем все секции начинающиеся с .text
                text_sections.append(section)
        
        if not text_sections:
            raise EXEParsingError("Секции .text не найдены")
            
        return [
            MachineCode(
                code=section.raw_data,
                virtual_address=section.virtual_address,
                raw_address=section.pointer_to_raw_data
            )
            for section in text_sections
        ]

    def display_info(self):
        """Выводит информацию о секциях, импортах и машинном коде"""

        sections = self.get_sections()
        imports = self.get_imports()
        
        splitter = '/' if self.file_path.count('/')>0 else '\\'
        print(f"Resolved {self.file_path.split(splitter)[-1]}:")
        print()
        print("Секции:")
        for section in sections:
            print(f"  {section}")

        print("\nТаблица импортов:")
        if not imports: 
            print("  Отсутствует")
        for imp in imports:
            print(f"  {imp.dll_name}: {', '.join(imp.functions)}")
            
        try:
            machine_codes = self.get_machine_code()
            print(f"\nНайдено секций с машинным кодом: {len(machine_codes)}")
            
            for i, machine_code in enumerate(machine_codes, 1):
                print(f"\nМашинный код #{i}:")
                print(f"  Виртуальный адрес: 0x{machine_code.virtual_address:X}")
                print(f"  Физический адрес: 0x{machine_code.raw_address:X}")
                print(f"  Размер: {len(machine_code.code)} байт")
                print("  Первые 32 байта:")
                print("  ", " ".join(f"{b:02X}" for b in machine_code.code[:32]))
                
                # Сохраняем в отдельные файлы для каждой секции
                self.save_machine_code(i, machine_code)
                
        except EXEParsingError as e:
            print("\nМашинный код: не удалось извлечь")

    def save_machine_code(self, i, machine_code : MachineCode):

        with open(OUTPUT_BIN_DIR(i), 'wb') as f:
            f.write(bytes(machine_code.code))
        print(f"  Машинный код сохранен в output_text_{i}.bin")