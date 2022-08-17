# using pycryptodome lib

from Crypto.Cipher import AES
import binascii
import hashlib
import tkinter as tk
from tkinter import *
import os

root = Tk()
root.geometry("700x400")
root.title("Data Encryption & Privacy")
root.resizable(True, False)
root.iconbitmap('locked.ico')
root.config(bg='orange')


def run():
    global user_message_entry
    global user_password_entry
    msgs = user_message_entry.get()
    sk = user_password_entry.get()
    filehandle = open("Encrypted Message and Key.txt", "w")

    def encrypt_AES_GCM(msg, secretKey):
        aesCipher = AES.new(secretKey, AES.MODE_GCM)
        ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
        return (ciphertext, aesCipher.nonce, authTag)

    sha3_256hash = hashlib.sha3_256(bytes(sk, 'ascii')).digest()
    secretKey = sha3_256hash  # 256-bit random encryption key
    filehandle.write(secretKey.hex())
    filehandle.write("\n")
    keyLable = Label(root, text="KEY: " + secretKey.hex(), bg='orange',
                     fg='white').place(x=40, y=170)

    msg = bytes(msgs, 'ascii')
    encryptedMsg = encrypt_AES_GCM(msg, secretKey)
    filehandle.write(encryptedMsg[0].hex())
    ciphertextLable = Label(root,  text="Cipher Text: " + encryptedMsg[0].hex(), bg='orange',
                            fg='white').place(x=40, y=190)
    filehandle.write("\n")
    filehandle.write(encryptedMsg[1].hex())
    aesCipherLable = Label(root,  text="aesCipher: " + encryptedMsg[1].hex(), bg='orange',
                           fg='white').place(x=40, y=210)
    filehandle.write("\n")
    filehandle.write(encryptedMsg[2].hex())
    authTagLable = Label(root,  text="Authentication Tag: " + encryptedMsg[2].hex(), bg='orange',
                         fg='white').place(x=40, y=230)
    filehandle.write("\n")

    filehandle.close()


user_message = Label(root, text="Message", bg='orange',
                     fg='white', font='Poppins').place(x=40, y=60)
user_password = Label(root, text="Password", bg='orange',
                      fg='white', font='Poppins').place(x=40, y=100)
submit_button = Button(root, text="Submit", bg='orange', fg='black',
                       command=run).place(x=40, y=130)

user_message_entry = Entry(root, width=30)
user_message_entry.place(x=110, y=60)
user_password_entry = Entry(root, width=30)
user_password_entry.place(x=110, y=100)

root.mainloop()
