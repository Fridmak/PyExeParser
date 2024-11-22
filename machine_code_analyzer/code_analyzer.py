from collections import defaultdict
from infrastructure.machine_code import MachineCode
from infrastructure.constants import (
    ASCII_PRINTABLE_MIN, ASCII_PRINTABLE_MAX,
    MIN_STRING_LENGTH
)
import re


class CodeAnalyzer:
    """Анализатор машинного кода"""

    def __init__(self, machine_codes: list[MachineCode]):
        self.machine_codes = machine_codes

    def find_patterns(self, pattern: bytes, section_index: [int | None] = None) -> dict[int, list[int]]:
        """
        Ищет байтовые паттерны в машинном коде
        
        Args:
            pattern: Искомый паттерн байтов
            section_index: Индекс конкретной секции для поиска (None для поиска во всех секциях)
        
        Returns:
            Dict[int, List[int]]: Словарь {индекс_секции: [найденные_адреса]}
        """

        results = {}
        sections_to_search = (
            [self.machine_codes[section_index]] if section_index is not None
            else self.machine_codes
        )

        for idx, machine_code in enumerate(sections_to_search):
            section_results = []
            code = machine_code.code

            matches = re.finditer(re.escape(pattern), code)
            for match in matches:
                section_results.append(match.start())

            if section_results:
                results[idx] = section_results

        return results

    def get_statistics(self, section_index: [int | None] = None) -> dict[int, dict[bytes, int]]:
        """Возвращает статистику по часто встречающимся байтам"""

        results = {}
        sections_to_analyze = (
            [self.machine_codes[section_index]] if section_index is not None
            else self.machine_codes
        )

        for idx, machine_code in enumerate(sections_to_analyze):
            stats = defaultdict(int)
            for b in machine_code.code:
                stats[b] += 1
            results[idx] = dict(sorted(stats.items(), key=lambda x: x[1], reverse=True))

        return results

    def find_strings(self, min_length: int = MIN_STRING_LENGTH, section_index: [int | None] = None) -> dict[
        int, list[tuple[int, str]]]:
        """Ищет ASCII строки в машинном коде"""

        results = {}
        sections_to_search = (
            [self.machine_codes[section_index]] if section_index is not None
            else self.machine_codes
        )

        for idx, machine_code in enumerate(sections_to_search):
            strings = []
            current_string = []
            start_addr = None

            for i, b in enumerate(machine_code.code):
                if ASCII_PRINTABLE_MIN <= b <= ASCII_PRINTABLE_MAX:
                    if not current_string:
                        start_addr = machine_code.virtual_address + i
                    current_string.append(chr(b))
                    continue
                if len(current_string) >= min_length:
                    strings.append((start_addr, ''.join(current_string)))
                current_string = []
                start_addr = None

            if strings:
                results[idx] = strings

        return results
