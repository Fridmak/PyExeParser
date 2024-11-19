class EXEParsingError(Exception):
    """Базовый класс для исключений парсинга EXE файлов."""
    pass


class UnsupportedFormatError(EXEParsingError):
    """Исключение для неподдерживаемых форматов EXE."""
    pass