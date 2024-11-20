import os

from infrastructure.constants import OUTPUT_BIN_DIR
from parsers.exe_parser import EXEParser
from infrastructure.errors import EXEParsingError, UnsupportedFormatError
from infrastructure.logs_writer import clear_logs

def main():
    handle_output()
    while True:
        exe_path = str(input("Введите файл для проверки: ")) #exe_files/notepad.exe

        try:
            parser = EXEParser(exe_path)
            parser.parse()
            parser.display_info()
        except (EXEParsingError, UnsupportedFormatError, FileNotFoundError) as e:
            print(f"Ошибка: {e}")
        print()

def handle_output():
    clear_logs()
    for i in range(1, 15):
        try:
            os.remove(OUTPUT_BIN_DIR(i))
        except:
            pass

if __name__ == "__main__":
    main()
