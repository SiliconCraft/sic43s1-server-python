from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import binascii

def s1_cmac(tag_time_stamp, tag_uid, tag_flag_tamper, server_key):
    byte_secret = bytearray.fromhex(server_key)
    plaintext = tag_time_stamp + tag_uid + tag_flag_tamper
    byte_plaintext = bytearray.fromhex(plaintext)

    cmac_obj = CMAC.new(byte_secret, msg=byte_plaintext, ciphermod=AES)

    return cmac_obj.hexdigest().upper()

def s1_ocb(nonce, ciphertext, mac, server_key):
    byte_secret = bytearray.fromhex(server_key)
    nonce = bytearray.fromhex(nonce)
    ciphertext = bytearray.fromhex(ciphertext)
    mac = bytearray.fromhex(mac)

    cipher = AES.new(byte_secret, AES.MODE_OCB, nonce, mac_len=4)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, mac)
    except ValueError:
        print("Invalid message")
    else:
        # print("decrypted:",binascii.hexlify(plaintext).upper().decode(), binascii.hexlify(mac).upper().decode())
        return binascii.hexlify(plaintext).upper().decode(), binascii.hexlify(mac).upper().decode()