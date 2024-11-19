import os
from Infrastructure.presentations import MachineCode
from Infrastructure.constants import (
    MIN_STRING_LENGTH, MAX_DISPLAY_BYTES, TOP_BYTES_COUNT,
    MAX_PATTERN_ADDRESSES, MACHINE_CODE_PATTERNS,
    BIN_EXTENSION
)
from code_analyzer import CodeAnalyzer

def load_machine_code(file_path: str) -> MachineCode:
    """Загружает машинный код из .bin файла"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Файл не найден: {file_path}")
        
    with open(file_path, 'rb') as f:
        code = f.read()
    
    return MachineCode(
        code=code,
        virtual_address=0,
        raw_address=0
    )

def display_file_info(file_path: str, machine_code: MachineCode):
    """Отображает базовую информацию о файле"""
    print(f"\nАнализ файла: {file_path}")
    print(f"Размер: {len(machine_code.code)} байт")
    
    print("\nПервые {} байта:".format(MAX_DISPLAY_BYTES))
    print(" ".join(f"{b:02X}" for b in machine_code.code[:MAX_DISPLAY_BYTES]))

def display_statistics(analyzer: CodeAnalyzer, machine_code: MachineCode):
    """Отображает статистику байтов"""
    stats = analyzer.get_statistics()
    print(f"\nТоп-{TOP_BYTES_COUNT} наиболее частых байтов:")
    for section_idx, section_stats in stats.items():
        top_bytes = list(section_stats.items())[:TOP_BYTES_COUNT]
        for byte, count in top_bytes:
            percentage = (count / len(machine_code.code)) * 100
            print(f"0x{byte:02X}: {count} раз ({percentage:.2f}%)")

def display_strings(analyzer: CodeAnalyzer):
    """Отображает найденные строки"""
    strings = analyzer.find_strings(min_length=MIN_STRING_LENGTH)
    if strings:
        print(f"\nНайденные ASCII строки (мин. длина {MIN_STRING_LENGTH}):")
        for section_idx, section_strings in strings.items():
            for addr, string in section_strings:
                print(f"0x{addr:X}: {string}")

def display_patterns(analyzer: CodeAnalyzer):
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

def analyze_file(file_path: str):
    """Анализирует .bin файл с машинным кодом"""
    try:
        machine_code = load_machine_code(file_path)
        analyzer = CodeAnalyzer([machine_code])
        
        display_file_info(file_path, machine_code)
        display_statistics(analyzer, machine_code)
        display_strings(analyzer)
        display_patterns(analyzer)
        
    except Exception as e:
        print(f"Ошибка при анализе файла: {e}")

def analyze():
    """Основной цикл анализа файлов"""
    while True:
        print("\nВведите путь к .bin файлу для анализа (или 'q' для выхода):")
        file_path = input().strip()
        
        if file_path.lower() == 'q':
            break
            
        if not file_path.endswith(BIN_EXTENSION):
            print(f"Файл должен иметь расширение {BIN_EXTENSION}")
            continue
            
        try:
            analyze_file(file_path)
        except Exception as e:
            print(f"Ошибка: {e}")

if __name__ == "__main__":
    analyze()
