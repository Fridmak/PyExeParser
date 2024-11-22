from dataclasses import dataclass


@dataclass
class Import:
    """Класс, представляющий импортированную функцию из DLL"""

    dll_name: str
    functions: list[str]

    def __repr__(self):
        return f"Import(DLL={self.dll_name}, Functions={self.functions})"


@dataclass
class ImportDescriptor:
    """Класс с представлением секции импорта"""

    original_first_thunk: bytes
    time_date_stamp: bytes
    forwarder_chain: bytes
    name_rva: int
    first_thunk: bytes
