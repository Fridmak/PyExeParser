from typing import List
from abc import ABC, abstractmethod

class Section:
    """Класс, представляющий секцию в EXE файле."""

    def __init__(self, name: str, virtual_address: int, virtual_size: int,
                 size_of_raw_data: int, pointer_to_raw_data: int, raw_data: bytes):
        self.name = name
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size
        self.size_of_raw_data = size_of_raw_data
        self.pointer_to_raw_data = pointer_to_raw_data
        self.raw_data = raw_data

    def __repr__(self):
        return (f"Section(name={self.name}, VA=0x{self.virtual_address:X}, "
                f"Size=0x{self.virtual_size:X}, RawDataOffset=0x{self.pointer_to_raw_data:X})")


class Import:
    """Класс, представляющий импортированную функцию из DLL."""

    def __init__(self, dll_name: str, functions: List[str]):
        self.dll_name = dll_name
        self.functions = functions

    def __repr__(self):
        return f"Import(DLL={self.dll_name}, Functions={self.functions})"


class HeaderParser(ABC):
    """Абстрактный базовый класс для парсеров заголовков EXE файлов."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.sections: List[Section] = []
        self.imports: List[Import] = []

    @abstractmethod
    def parse(self):
        """Парсит заголовок и секции EXE файла."""
        pass

    @abstractmethod
    def get_imports(self) -> List[Import]:
        """Возвращает таблицу импортов."""
        pass

class ImportDescriptor:
    def __init__(self, original_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk):
        self.original_first_thunk = original_first_thunk
        self.time_date_stamp = time_date_stamp
        self.forwarder_chain = forwarder_chain
        self.name_rva = name_rva
        self.first_thunk = first_thunk

class MachineCode:
    """Класс для представления машинного кода"""
    def __init__(self, code: bytes, virtual_address: int, raw_address: int):
        self.code = code
        self.virtual_address = virtual_address
        self.raw_address = raw_address

    def __repr__(self):
        return f"MachineCode(VA=0x{self.virtual_address:X}, RawAddr=0x{self.raw_address:X}, Size={len(self.code)})"