import socket
from struct import pack
from typing import List


class RopChain:
    def __init__(self, base=None, pack_str='<I', chain=b''):
        self.chain = chain
        self.base = base or 0
        self.pack_str = pack_str

    def __iadd__(self, other):
        if isinstance(other, int):
            self.chain += self._pack_32(self.base + other)
        elif isinstance(other, bytes):
            self.chain += other
        else:
            raise NotImplementedError
        return self

    def __len__(self) -> int:
        return len(self.chain)

    @staticmethod
    def p32(address) -> bytes:
        return pack('<I', address)

    def _pack_32(self, address) -> bytes:
        return pack(self.pack_str, address)

    def append_raw(self, address):
        """ just ignore the base address; useful for actual values in conjunction with pop r32 """
        self.chain += pack(self.pack_str, address)


def get_connection(ip: str, port: int) -> socket.socket:
    sock = None
    while sock is None:
        try:
            sock = socket.create_connection((ip, port))
        except ConnectionRefusedError:
            continue
    return sock


def sanity_check(byte_str: bytes, bad_chars: List[int]):
    baddies = list()

    for bc in bad_chars:
        if bc in byte_str:
            print(f"[!] bad char found: {hex(bc)}")
            baddies.append(bc)

    if baddies:
        print(f"[=] {byte_str}")
        print("[!] Remove bad characters and try again")
        raise SystemExit
