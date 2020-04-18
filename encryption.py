from Cryptodome.Cipher import AES
key = b"11"*16
iv=b'00'*16
cipher = AES.new(key, AES.MODE_CTR)


data = (1,23, 3)

data = data.

cipher.encrypt(data)