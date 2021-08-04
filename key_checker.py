from hashlib import sha256

from Crypto.Cipher import Blowfish


def make_key(key):
    key = key + b'\x02\x07\x1C\x11\x00\x00\x00\x00\x0A\x04\x00\x39\x0F\x01\x38\x00\x38\x01\x00'

    h = sha256(key)
    dig = h.digest()
    return dig


def check_key(key, ctr, data):
    dig = make_key(key)

    bf = Blowfish.new(dig, Blowfish.MODE_CTR, counter=ctr)
    cfld = bf.decrypt(data)

    if cfld[:4] == b'ICLD':
        print('Password: %s' % key)
        return True

    return False
