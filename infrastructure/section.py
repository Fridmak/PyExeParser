from dataclasses import dataclass


@dataclass
class Section:
    """Класс, представляющий секцию в EXE файле"""

    name: str
    virtual_address: int
    virtual_size: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    raw_data: bytes

    def __repr__(self):
        return (f"Section(name={self.name}, VA=0x{self.virtual_address:X}, "
                f"Size=0x{self.virtual_size:X}, RawDataOffset=0x{self.pointer_to_raw_data:X})")
