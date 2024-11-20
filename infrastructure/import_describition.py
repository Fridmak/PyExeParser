from typing import List


class Import:
    """Класс, представляющий импортированную функцию из DLL"""

    def __init__(self, dll_name: str, functions: List[str]):
        self.dll_name = dll_name
        self.functions = functions

    def __repr__(self):
        return f"Import(DLL={self.dll_name}, Functions={self.functions})"


class ImportDescriptor:
    def __init__(self, original_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk):
        self.original_first_thunk = original_first_thunk
        self.time_date_stamp = time_date_stamp
        self.forwarder_chain = forwarder_chain
        self.name_rva = name_rva
        self.first_thunk = first_thunk
