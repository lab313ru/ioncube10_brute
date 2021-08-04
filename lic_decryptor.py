import itertools
import struct
import sys
from base64 import b64decode
from Crypto.Util import Counter
import multiprocessing as mp

from key_checker import check_key


def decode_dword(buf):
    res = 0

    for i in range(4):
        b0 = struct.unpack_from('B', buf, i * 2)[0]

        if b0 > ord('9'):
            b0 = ((2 - b0) & 0xFF) << 4
        else:
            b0 <<= 4
        b0 &= 0xFF

        b1 = struct.unpack_from('B', buf, i * 2 + 1)[0]

        if b1 > ord('9'):
            b1 = (ord('c') - b1) | b0
        else:
            b1 = (b1 - ord('0')) | b0

        res |= b1 << (i * 8)
        res &= 0xFFFFFFFF

    return res


class MT:
    def __init__(self, seed: int) -> None:
        self.state = [0] * (4 + 624)
        self.i = 624
        self.consts = [0, 0x9908B0DF]

        for i in range(4):
            self.state[i] = 0

        for i in range(624):
            self.state[4 + i] = seed & 0xFFFF0000
            self.state[4 + i] = (self.state[4 + i] | ((((0x10DCD * seed) & 0xFFFFFFFF) + 1) >> 16)) & 0xFFFFFFFF
            seed = (0x10DCD * (((seed * 0x10DCD) & 0xFFFFFFFF) + 1) + 1) & 0xFFFFFFFF

    def twist(self) -> None:
        pass

    def get_dword(self) -> int:
        if self.i >= 624:
            i = -4

            while i < 0:
                self.state[4 + i] = self.state[4 + i + 624]
                i += 1

            while i < (624 - 397):
                dw = ((self.state[4 + i + 1] ^ self.state[4 + i]) & 0x7FFFFFFF) ^ self.state[4 + i]
                self.state[4 + i] = self.consts[dw & 1] ^ self.state[4 + i + 397] ^ (dw >> 1)
                i += 1

            while i < (624 - 1):
                dw = ((self.state[4 + i + 1] ^ self.state[4 + i]) & 0x7FFFFFFF) ^ self.state[4 + i]
                self.state[4 + i] = self.state[4 + i - 624 + 397] ^ self.consts[dw & 1] ^ (dw >> 1)
                i += 1

            i = 4 + 624 - 1
            dw = ((self.state[4] ^ self.state[i]) & 0x7FFFFFFF) ^ self.state[i]
            self.state[i] = self.consts[dw & 1] ^ self.state[4 + 397 - 1] ^ (dw >> 1)

            self.i = 0

        rnd = self.state[4 + self.i]
        self.i += 1

        rnd = (rnd ^ (rnd >> 11)) & 0xFFFFFFFF
        rnd = (rnd ^ ((rnd & 0xFF3A58AD) << 7)) & 0xFFFFFFFF
        rnd = (rnd ^ ((rnd & 0xFFFFDF8C) << 15)) & 0xFFFFFFFF
        return (rnd >> 18) ^ rnd


def gen_b64_alpha(seeder):
    alpha = bytearray([0] * 64)
    tmp = bytearray([0] * 8)

    for i in range(64):
        idx = i >> 3

        while True:
            v2 = seeder.get_dword() & 0x3F
            idx = v2 >> 3

            if tmp[idx] & (1 << (v2 & 7)) == 0:
                break

        tmp[idx] |= 1 << (v2 & 7)
        alpha[i] = v2 + ord('0')

        if v2 >= 0x0A:
            alpha[i] = v2 + ord('7')

        if v2 >= 0x24:
            alpha[i] = v2 + ord('=')

        if v2 >= 0x3E:
            alpha[i] = b'+/'[0x3F - v2]

    return bytes(alpha)


def main(path):
    f = open(path)
    data = f.read().encode()
    f.close()

    p0 = data.find(b'------ LICENSE FILE DATA -------')

    if p0 == -1:
        return

    p1 = data.find(b'--------------------------------')

    if p1 == -1:
        return

    data = data[32+p0:p1].replace(b'\n', b'').replace(b'\r\n', b'')

    seed = decode_dword(data)
    data = data[8:]

    mt = MT(seed)

    b64alpha = gen_b64_alpha(mt)

    std_base64chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    data = data.translate(bytes.maketrans(b64alpha, std_base64chars))

    data = bytearray(b64decode(data))

    mt = MT(seed)

    for i, ch in enumerate(data):
        data[i] ^= mt.get_dword() & 0xFF

    data = bytes(data)

    if data[:4] != b'ICLF':
        return

    d0 = struct.unpack('>I', data[6 + 0:6 + 4])[0]
    d1 = struct.unpack('>I', data[6 + 4:6 + 8])[0]

    dd = (d0 << 32) | d1
    ctr = Counter.new(64, initial_value=dd)

    pool = mp.Pool(mp.cpu_count())
    data = data[6+8:]

    x = open(sys.argv[2], 'rb')
    lines = x.read().splitlines()
    print('total lines: %d' % len(lines))
    results = pool.starmap_async(check_key, [(item, ctr, data) for item in lines])
    x.close()


if __name__ == '__main__':
    main(sys.argv[1])
