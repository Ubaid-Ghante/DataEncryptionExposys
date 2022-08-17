# using pycryptodome lib

from Crypto.Cipher import AES
import binascii
import os
import hashlib


filehandle = open("Encrypted Message and Key.txt", "w")


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)


sk = input("\n\nEnter password for your message\n")
sha3_256hash = hashlib.sha3_256(bytes(sk, 'ascii')).digest()
secretKey = sha3_256hash  # 256-bit random encryption key
filehandle.write(secretKey.hex())
filehandle.write("\n")

msgs = input("\n\nEnter your message:\n")
msg = bytes(msgs, 'ascii')
encryptedMsg = encrypt_AES_GCM(msg, secretKey)
filehandle.write(encryptedMsg[0].hex())
filehandle.write("\n")
filehandle.write(encryptedMsg[1].hex())
filehandle.write("\n")
filehandle.write(encryptedMsg[2].hex())
filehandle.write("\n")

filehandle.close()
