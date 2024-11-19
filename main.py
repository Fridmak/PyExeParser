import os

from Parsers.exe_parser import EXEParser
from Infrastructure.errors import EXEParsingError, UnsupportedFormatError
from Infrastructure.logs_writer import clear_logs

def main():
    handle_output()
    while True:
        exe_path = str(input("Введите файл для проверки: ")) #ExeFiles/calc.exe

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
            os.remove(f"output_text_{i}.bin")
        except:
            pass

if __name__ == "__main__":
    main()
