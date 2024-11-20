class Section:
    """Класс, представляющий секцию в EXE файле"""

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