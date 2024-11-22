from dataclasses import dataclass


@dataclass
class MachineCode:
    """Класс для представления машинного кода"""

    code: bytes
    virtual_address: int
    raw_address: int

    def __repr__(self):
        return f"MachineCode(VA=0x{self.virtual_address:X}, RawAddr=0x{self.raw_address:X}, Size={len(self.code)})"
