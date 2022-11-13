import base64
import hashlib
import math
import struct

import pandas as pd
from Crypto.Cipher import ARC4

enc_msg = base64.b64decode(
    "TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg=="
)


def get_index(timedata: bytes) -> int:
    (
        year,
        month,
        _day_of_week,
        day,
        _hour,
        _minute,
        _second,
        _milliseconds,
    ) = struct.unpack("<HHHHHHHH", timedata)
    ts = pd.Timestamp(year=year, month=month, day=day)
    julian_date = ts.to_julian_date()
    num = (julian_date - 2451549.5) / 29.53
    delta = num - math.floor(num)
    return round(delta * 29.53)


def get_chr(index: int) -> str:
    alphabet = " abcdefghijklmnopqrstuvwxyz\x000_3"
    if index > 26:
        return alphabet[index + 1]
    return alphabet[index]


def get_rc4key(suf: str) -> bytes:
    return hashlib.md5(f"FO9{suf}".encode("utf-16le")).hexdigest()


def check_key(key: str, enc: bytes, dec: bytes):
    cipher = ARC4.new(key.encode("utf-16le"))
    return cipher.decrypt(enc) == dec


def decrypt(enc_data: bytes, key: str) -> bytes:
    cipher = ARC4.new(key.encode("utf-16le"))
    return cipher.decrypt(enc_data)


def get_key() -> str:
    alphabet = [f"{c:02x}".upper() for c in range(256)]
    hexdigs = "0123456789ABCDEF"

    test_enc = base64.b64decode("ydN8BXq16RE=")
    test_dec = "ahoy".encode("utf-16le")

    for x in alphabet:
        for y in alphabet:
            for z in hexdigs:
                suf = f"{x}{y}{z}"
                key = get_rc4key(suf)
                if check_key(key, test_enc, test_dec):
                    return key
    return str()


key = get_key()

assert len(key)

print(f"RC4 Key: {key}")
dec = decrypt(enc_msg, key)

result = str()
for timedata in dec.split(b"\x2c\x00"):
    result += get_chr(get_index(timedata))

print(f"Flag: {result}@flare-on.com")
# i_s33_you_m00n@flare-on.com
