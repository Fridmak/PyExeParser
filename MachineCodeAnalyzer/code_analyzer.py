from typing import List, Dict, Optional
from Infrastructure.presentations import MachineCode
from Infrastructure.constants import (
    ASCII_PRINTABLE_MIN, ASCII_PRINTABLE_MAX,
    MIN_STRING_LENGTH
)

class CodeAnalyzer:
    """Анализатор машинного кода"""
    
    def __init__(self, machine_codes: List[MachineCode]):
        self.machine_codes = machine_codes
        
    def find_patterns(self, pattern: bytes, section_index: Optional[int] = None) -> Dict[int, List[int]]:
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
            
            for i in range(len(code) - len(pattern) + 1):
                if code[i:i+len(pattern)] == pattern:
                    section_results.append(machine_code.virtual_address + i)
            
            if section_results:
                results[idx] = section_results
                
        return results
        
    def get_statistics(self, section_index: Optional[int] = None) -> Dict[int, Dict[bytes, int]]:
        """Возвращает статистику по часто встречающимся байтам"""
        results = {}
        sections_to_analyze = (
            [self.machine_codes[section_index]] if section_index is not None 
            else self.machine_codes
        )
        
        for idx, machine_code in enumerate(sections_to_analyze):
            stats = {}
            for b in machine_code.code:
                stats[b] = stats.get(b, 0) + 1
            results[idx] = dict(sorted(stats.items(), key=lambda x: x[1], reverse=True))
            
        return results

    def find_strings(self, min_length: int = MIN_STRING_LENGTH, section_index: Optional[int] = None) -> Dict[int, List[tuple[int, str]]]:
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
                else:
                    if len(current_string) >= min_length:
                        strings.append((start_addr, ''.join(current_string)))
                    current_string = []
                    start_addr = None
            
            if strings:
                results[idx] = strings
                
        return results