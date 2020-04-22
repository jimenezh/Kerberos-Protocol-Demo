from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import AES
from os import urandom


def to_bytes(elem):
    if(type(elem) == bytes):
        return elem
    if(type(elem) != str):
        return str(elem).encode()
    return elem.encode()


def to_original_type(elem):

    result = None
    try:
        temp = elem.decode()
        result = int(temp)
    except:
        result = elem

    return result


def encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), default_backend())
    enc = cipher.encryptor()
    ctext = [0]*len(data)

    if(type(data) != list):
        
        ctext = enc.update(to_bytes(data))
      
    else:
        for i in range(len(data)):
     
            ctext[i] = enc.update(to_bytes(data[i]))

    enc.finalize()
  

    return ctext


def decrypt(ctext, key, iv):
    cipher = Cipher(algorithms.AES(key),
                    modes.CTR(iv), default_backend())
    dec = cipher.decryptor()
    plain = [0]*len(ctext)


    if(type(ctext) != list):
       return dec.update(ctext)
    else:
        for i in range(len(ctext)):
            plain[i] = to_original_type(dec.update(ctext[i]))

    dec.finalize()

    return plain


def create_random_16_bytes():
    return urandom(16)


# key = b'\x00'*16
# data = ['hello', 'goddbye', 34]
# c = encrypt(data, key, key)
# p = decrypt(c, key, key)
# print(c)
# print(p)
