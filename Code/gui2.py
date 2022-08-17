from Crypto.Cipher import AES
import binascii
import os
import hashlib
from tkinter import *
import os

root2 = Tk()
root2.geometry("400x400")
root2.title("Data Encryption & Privacy")
root2.iconbitmap('locked.ico')
root2.config(bg='orange')


def run():
    global user_password_entry
    sk = user_password_entry.get()

    filehandle = open("Encrypted Message and Key.txt", "r")
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
        decryptedLable = Label(root2, text=b'Decrypted Message : ' +
                               decryptedMsg, bg='orange', fg='white').place(x=40, y=160)
        filehandle2.close()
    else:
        print("Wrong password")
        decryptedLable = Label(root2, text='Wrong password',
                               bg='orange', fg='white').place(x=40, y=160)
    filehandle.close()


user_password = Label(root2, text="Password", bg='orange',
                      fg='white', font='Poppins').place(x=40, y=60)
user_password_entry = Entry(root2, width=30)
user_password_entry.place(x=110, y=60)
submit_button = Button(root2, text="Submit", bg='orange', fg='black',
                       command=run).place(x=40, y=130)


root2.mainloop()
