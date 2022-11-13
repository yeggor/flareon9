import binascii
import string

test_pwd = b"12344.."
test_out = b"=2..K92"

flag_enc_start = binascii.hexlify(
    bytes([test_pwd[i] ^ test_out[i] for i in range(len(test_pwd))])
)
print(f"{flag_enc_start = }")

# pattern starting with flag_enc_start in the binary
enc = binascii.unhexlify(
    "0c001d1a7f171c4e0211280810480500001a7f2af61744320ffc1a602c08101c6002194117115a0e1d0e390a042718"
)


def check(dec):
    for c in dec:
        if chr(c) not in string.printable:
            return False
    return True


suf = b"@flare-on.com"
for i in range(0, len(enc) - len(suf), 1):
    chunk = enc[i : i + len(suf)]
    dec = bytes([chunk[j] ^ suf[j] for j in range(len(suf))])
    if check(dec):
        print(dec)

# b'Lfq{\rr1!l?Kg}'
# b'Pz\x0cck$:~4 ~aT'
# b' du etwas Zei'
# => key = "Hast du etwas Zeit für mich"
# flag = "Dann_singe_ich_ein_Lied_fur_dich@flare-on.com"
