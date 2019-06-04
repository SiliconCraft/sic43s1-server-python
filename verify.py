from Crypto.Hash import CMAC
from Crypto.Cipher import AES

def s1_cmac(tag_time_stamp, tag_uid, tag_flag_tamper, server_key):
    byte_secret = bytearray.fromhex(server_key)
    plaintext = tag_time_stamp + tag_uid + tag_flag_tamper
    byte_plaintext = bytearray.fromhex(plaintext)

    cmac_obj = CMAC.new(byte_secret, msg=byte_plaintext, ciphermod=AES)
    return cmac_obj.hexdigest().upper()

def s1_ocb():
    ## In development ##
    return