from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

class DataEncryption:
    def __init__(self):
        # self.key = str(k).encode("utf-8")
        # self.iv = str(i).encode("utf-8")
        self.key = b'helloghdifjghcbv'
        self.iv = b'jdufhcndmvnchfue'

    def encrypt(self, data):
        data = data.encode("utf-8")
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        # iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        return ct

    def decrypt(self, data):
        ci = AES.new(self.key, AES.MODE_CBC, self.iv)
        dec = unpad(ci.decrypt(b64decode(data+ "==")), AES.block_size)
        return dec.decode("utf-8")

