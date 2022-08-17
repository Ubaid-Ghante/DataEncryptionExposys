from Crypto.Cipher import AES
import binascii
import os
import hashlib

filehandle = open("Encrypted Message and Key.txt", "r")
sk = input("\n\nEnter password for your message\n")
sha3_256hash = hashlib.sha3_256(bytes(sk, 'ascii')).digest()
secretKey = sha3_256hash  # 256-bit random encryption key
sh = secretKey.hex()
key = filehandle.readline().strip("\n")


encryptedMsg = (bytes.fromhex(filehandle.readline()), bytes.fromhex(
    filehandle.readline()), bytes.fromhex(filehandle.readline()))


def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext


if (key == sh):
    decryptedMsg = decrypt_AES_GCM(encryptedMsg, secretKey)
    filehandle2 = open("Output.txt", "wb")
    filehandle2.write(decryptedMsg)
    filehandle2.close()
else:
    print("Wrong password")
filehandle.close()
