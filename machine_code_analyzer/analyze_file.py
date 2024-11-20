import os
from typing import List

from infrastructure.machine_code import MachineCode
from infrastructure.constants import (
    MIN_STRING_LENGTH, MAX_DISPLAY_BYTES, TOP_BYTES_COUNT,
    MAX_PATTERN_ADDRESSES, MACHINE_CODE_PATTERNS, OUTPUT_ASSEMBLY_DIR, OUTPUT_BIN_DIR
)
from code_analyzer import CodeAnalyzer
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


class GeneralInfo:
    """Class which gets general information from .bin files"""

    def __init__(self, file_path: str):
        self.file_path: str = file_path

    def get(self) -> None:
        """Анализирует .bin файл с машинным кодом"""

        try:
            machine_code = self.load_machine_code()
            analyzer = CodeAnalyzer([machine_code])

            self.display_file_info(machine_code)
            self.display_statistics(analyzer, machine_code)
            self.display_strings(analyzer)
            self.display_patterns(analyzer)

        except Exception as e:
            print(f"Ошибка при анализе файла: {e}")

    def load_machine_code(self) -> MachineCode:
        """Загружает машинный код из .bin файла"""

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Файл не найден: {self.file_path}")

        with open(self.file_path, 'rb') as f:
            code = f.read()

        return MachineCode(
            code=code,
            virtual_address=0,
            raw_address=0
        )

    def display_file_info(self, machine_code: MachineCode) -> None:
        """Отображает базовую информацию о файле"""

        print(f"\nАнализ файла: {self.file_path}")
        print(f"Размер: {len(machine_code.code)} байт")

        print("\nПервые {} байта:".format(MAX_DISPLAY_BYTES))
        print(" ".join(f"{b:02X}" for b in machine_code.code[:MAX_DISPLAY_BYTES]))

    def display_statistics(self, analyzer: CodeAnalyzer, machine_code: MachineCode) -> None:
        """Отображает статистику байтов"""

        stats = analyzer.get_statistics()
        print(f"\nТоп-{TOP_BYTES_COUNT} наиболее частых байтов:")
        for section_idx, section_stats in stats.items():
            top_bytes = list(section_stats.items())[:TOP_BYTES_COUNT]
            for byte, count in top_bytes:
                percentage = (count / len(machine_code.code)) * 100
                print(f"0x{byte:02X}: {count} раз ({percentage:.2f}%)")

    def display_strings(self, analyzer: CodeAnalyzer) -> None:
        """Отображает найденные строки"""

        strings = analyzer.find_strings(min_length=MIN_STRING_LENGTH)
        if strings:
            print(f"\nНайденные ASCII строки (мин. длина {MIN_STRING_LENGTH}):")
            for section_idx, section_strings in strings.items():
                for addr, string in section_strings:
                    print(f"0x{addr:X}: {string}")

    def display_patterns(self, analyzer: CodeAnalyzer) -> None:
        """Отображает найденные паттерны машинного кода"""

        print("\nПоиск типичных паттернов:")
        for pattern, description in MACHINE_CODE_PATTERNS:
            results = analyzer.find_patterns(pattern)
            for section_idx, addresses in results.items():
                if addresses:
                    print(f"{description}:")
                    print(f"Найдено {len(addresses)} вхождений")
                    print("Первые {} адресов: {}".format(
                        MAX_PATTERN_ADDRESSES,
                        ", ".join(f"0x{addr:X}" for addr in addresses[:MAX_PATTERN_ADDRESSES])
                    ))


class BinFileToAssembly():
    """Reads machine code and returns assembly code"""

    def __init__(self, file_path: str):
        self.file_path = file_path

    def get(self) -> None:
        """Gets assembly code"""

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        codes : List[bytes] = []
        with open(self.file_path, 'rb') as f:
            codes.append(f.read())

        print(f"Дизассемблированный код выведен в {OUTPUT_ASSEMBLY_DIR("")}")
        for i, bin_code in enumerate(codes, 1):
            with open (OUTPUT_ASSEMBLY_DIR(i), "w") as t:
                t.write(f"Assembly code from .text_{i}: \n")
                for instruction in md.disasm(bin_code, 0):
                    t.write(f"0x{instruction.address:X}:\t{instruction.mnemonic}\t{instruction.op_str} \n")
                t.write("\n")


class MachineCodeAnalyzer():
    """General class for machine code analyzing"""

    @staticmethod
    def analyze() -> None:
        """Основной цикл анализа файлов"""

        while True:
            print("\nВведите путь к .bin файлу для анализа (или 'q' для выхода):")
            file_path = input().strip()

            if file_path.lower() == 'q':
                break

            if not file_path.endswith('.bin'):
                print(f"Файл должен иметь расширение {'.bin'}")
                continue

            try:
                choose = str(input("Что вы хотите получить? [common] or [assembly_code]: "))
                if choose == 'common':
                    general_info = GeneralInfo(file_path)
                    general_info.get()
                if choose == 'assembly_code':
                    assemly_code = BinFileToAssembly(file_path)
                    assemly_code.get()
            except Exception as e:
                print(f"Ошибка: {e}")


if __name__ == "__main__":
    MachineCodeAnalyzer.analyze()
