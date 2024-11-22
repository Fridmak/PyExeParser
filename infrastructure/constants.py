from pathlib import Path

#FILES
ROOT_DIR = Path(__file__).parent.parent.absolute()
LOGS_FILE = ROOT_DIR / 'log.txt'
OUTPUT_DIR = ROOT_DIR / "output"
OUTPUT_BIN_DIR = lambda i: OUTPUT_DIR / f'output_bin_{i}.bin'
OUTPUT_ASSEMBLY_DIR = lambda i: OUTPUT_DIR / f'output_assembly_{i}.txt'

MZ_HEADER_SIZE = 64
PE_HEADER_SIZE = 24
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
IMPORT_DESCRIPTOR_SIZE = 20
SECTION_NAME_LENGTH = 8
DIRECTORY_ENTRY_SIZE = 8

BYTE_SIZE = 1
WORD_SIZE = 2
DWORD_SIZE = 4
QWORD_SIZE = 8

MZ_SIGNATURE = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'
PE32_MAGIC = 0x10b
PE32_PLUS_MAGIC = 0x20b

E_LFANEW_OFFSET = 60
NUMBER_OF_RVA_SIZES_OFFSET = 88
DATA_DIRECTORY_PE32_OFFSET = 96
DATA_DIRECTORY_PE32PLUS_OFFSET = 112
OPTIONAL_HEADER_MAGIC_OFFSET = 0
IMPORT_DIRECTORY_OFFSET = 8

NULL_TERMINATED_BUFFER = 256
MAX_SECTION_COUNT = 96
MIN_HEADER_SIZE = 40

ORDINAL_FLAG_PE32 = 0x80000000
ORDINAL_FLAG_PE32_PLUS = 0x8000000000000000
ORDINAL_MASK = 0xFFFF

EXPORT_TABLE_INDEX = 0
IMPORT_TABLE_INDEX = 1
RESOURCE_TABLE_INDEX = 2
EXCEPTION_TABLE_INDEX = 3
CERTIFICATE_TABLE_INDEX = 4
RELOCATION_TABLE_INDEX = 5
DEBUG_TABLE_INDEX = 6
ARCHITECTURE_TABLE_INDEX = 7
GLOBAL_PTR_TABLE_INDEX = 8
TLS_TABLE_INDEX = 9
LOAD_CONFIG_TABLE_INDEX = 10
BOUND_IMPORT_TABLE_INDEX = 11
IAT_TABLE_INDEX = 12
DELAY_IMPORT_TABLE_INDEX = 13
COM_DESCRIPTOR_TABLE_INDEX = 14

# Анализ машинного кода
MIN_STRING_LENGTH = 4
MAX_DISPLAY_BYTES = 32
TOP_BYTES_COUNT = 10
MAX_PATTERN_ADDRESSES = 5

# Паттерны машинного кода
MACHINE_CODE_PATTERNS = [
    (b"\x55\x8B\xEC", "Пролог функции (x86)"),
    (b"\x48\x89\x5C\x24", "Пролог функции (x64)"),
    (b"\xCC", "INT 3 (точка останова)"),
    (b"\xC3", "RET"),
    (b"\x90", "NOP"),
]

# ASCII коды
ASCII_PRINTABLE_MIN = 32
ASCII_PRINTABLE_MAX = 126