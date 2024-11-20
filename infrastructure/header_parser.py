from typing import List
from abc import ABC, abstractmethod
from infrastructure.section import Section
from infrastructure.import_describition import Import


class BaseHeaderParser(ABC):
    """Абстрактный базовый класс для парсеров заголовков EXE файлов"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.sections: List[Section] = []
        self.imports: List[Import] = []

    @abstractmethod
    def parse(self):
        """Парсит заголовок и секции EXE файла"""
        pass

    @abstractmethod
    def get_imports(self) -> List[Import]:
        """Возвращает таблицу импортов"""
        pass
