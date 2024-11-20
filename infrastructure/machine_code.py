class MachineCode:
    """Класс для представления машинного кода"""

    def __init__(self, code: bytes, virtual_address: int, raw_address: int):
        self.code = code
        self.virtual_address = virtual_address
        self.raw_address = raw_address

    def __repr__(self):
        return f"MachineCode(VA=0x{self.virtual_address:X}, RawAddr=0x{self.raw_address:X}, Size={len(self.code)})"
