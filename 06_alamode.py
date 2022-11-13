import binascii

from Crypto.Cipher import ARC4

key = binascii.unhexlify("558bec83ec20ebfe")
enc_password = binascii.unhexlify("3e3951fba211f7b92c")
enc_flag = binascii.unhexlify(
    "e160a118932e96ad73bb4a92de180aaa4174adc01d9f3f19ff2b02dbd1cd1a"
)

cipher = ARC4.new(key)
print(cipher.decrypt(enc_password))
print(cipher.decrypt(enc_flag))
# M1x3d_M0dE_4_l1f3@flare-on.com
