import struct

import lief
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.cil.error import MethodBodyFormatError
from hashes import HASHES
from tokens import TOKENS

key = b"\x12\x78\xab\xdf"
excl = ["5aeb2b97"]
original_filename = "FlareOn.Backdoor.exe"
patched_filename = (
    "patch.exe"  # before running the script is just a copy of FlareOn.Backdoor.exe
)


class MethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, data: bytes):
        self.data: bytes = data
        self.offset: int = 0

    def read(self, n: int) -> bytes:
        res: bytes = self.data[self.offset : self.offset + n]
        self.offset += n
        return res

    def tell(self) -> int:
        return self.offset

    def seek(self, offset: int) -> int:
        self.offset = offset
        return self.offset


def ksa(key):
    keylength = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def prga(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        yield K


def rc4(key):
    s = ksa(key)
    return prga(s)


def rc4_cipher(enc, key):
    keystream = rc4(key)
    return bytes([enc[i] ^ next(keystream) for i in range(len(enc))])


def read_data(offset, size):
    data = None
    with open(original_filename, "rb") as f:
        f.seek(offset)
        data = f.read(size)
    return data


def replace_tokens(code):
    for token in TOKENS:
        rf, rt = struct.pack("<I", token), struct.pack("<I", TOKENS[token])
        code = code.replace(rf, rt)
    return code


def patch(code, offset):
    with open(patched_filename, "rb") as f:
        data = f.read()
    with open(patched_filename, "wb") as f:
        f.write(data[:offset] + code + data[offset + len(code) :])


if __name__ == "__main__":
    pe = lief.PE.parse(original_filename)
    for s in pe.sections:
        if len(s.name) != 8 or s.name in excl:
            continue
        print(f"\n\nsection_name: {s.name}, section_size: {s.virtual_size}")
        code = rc4_cipher(read_data(s.offset, s.virtual_size), key)
        code = replace_tokens(code)
        mbr = MethodBodyReader(code)
        while True:
            try:
                insn = mbr.read_instruction()
                print(insn)
            except MethodBodyFormatError:
                break
        offset, name, _, _ = HASHES[s.name]
        # if name == "flared_57":
        #     continue
        patch(code, offset)
