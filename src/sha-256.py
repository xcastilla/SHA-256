from typing import List
import argparse
import hashlib


class SHA256:
    def __init__(self):
        self.BLOCK_SIZE = 512
        self.BLOCK_SIZE_BYTES = int(self.BLOCK_SIZE / 8)
        self.hashes = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        self.constants = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    def hash(self, text: str) -> str:
        blob = bytearray(text, encoding='utf-8')
        blob = self.__pad_string(blob)
        for pos in range(0, len(blob), self.BLOCK_SIZE_BYTES):
            chunk = blob[pos:pos + self.BLOCK_SIZE_BYTES]

            # Create message schedule
            schedule = self.__create_schedule(chunk)
            for i in range(16, 64):
                s_0 = self.__s0(int.from_bytes(schedule[i - 15], byteorder='big'))
                s_1 = self.__s1(int.from_bytes(schedule[i - 2], byteorder='big'))
                w_i = int.from_bytes(schedule[i - 16], byteorder='big') + s_0 \
                    + int.from_bytes(schedule[i - 7], byteorder='big') + s_1
                w_i = w_i % 2**32
                schedule[i] = w_i.to_bytes(4, byteorder='big')  # type: ignore

            updated_hashes = self.hashes.copy()
            a, b, c, d, e, f, g, h = updated_hashes

            # Compression stage
            for i in range(64):
                cs_1 = self.__cs1(e)
                ch = (e & f) ^ (~e & g)
                temp1 = (h + cs_1 + ch + self.constants[i] + int.from_bytes(schedule[i], byteorder='big')) % 2**32
                cs_0 = self.__cs0(a)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (cs_0 + maj) % 2**32
                h = g
                g = f
                f = e
                e = (d + temp1) % 2**32
                d = c
                c = b
                b = a
                a = (temp1 + temp2) % 2**32

            # Modify hashes with the result of the compression loop
            updated_hashes[0] = (updated_hashes[0] + a) % 2**32
            updated_hashes[1] = (updated_hashes[1] + b) % 2**32
            updated_hashes[2] = (updated_hashes[2] + c) % 2**32
            updated_hashes[3] = (updated_hashes[3] + d) % 2**32
            updated_hashes[4] = (updated_hashes[4] + e) % 2**32
            updated_hashes[5] = (updated_hashes[5] + f) % 2**32
            updated_hashes[6] = (updated_hashes[6] + g) % 2**32
            updated_hashes[7] = (updated_hashes[7] + h) % 2**32

        # Create final digest from the concatenated updated hashes
        digest = ''.join(format(h, '08x') for h in updated_hashes)
        return digest

    def __pad_string(self, blob: bytearray) -> bytearray:
        text_length = 8 * len(blob)
        blob.append(0x80)
        while ((len(blob) * 8) + 64) % 512 != 0:
            blob.append(0x00)
        blob += text_length.to_bytes(8, byteorder='big')
        return blob

    def __create_schedule(self, chunk: bytearray) -> List[bytearray]:
        schedule = []
        for i in range(0, len(chunk), 4):
            schedule.append(chunk[i: i + 4])
        for i in range(48):
            schedule.append((0).to_bytes(4, byteorder='big'))  # type: ignore
        return schedule

    def __right_rotate(self, word: int, positions: int) -> int:
        return word << (32 - positions) | word >> positions

    def __right_shift(self, word: int, positions: int) -> int:
        return word >> positions

    def __s0(self, word: int) -> int:
        return self.__right_rotate(word, 7) ^ self.__right_rotate(word, 18) ^ self.__right_shift(word, 3)

    def __s1(self, word: int) -> int:
        return self.__right_rotate(word, 17) ^ self.__right_rotate(word, 19) ^ self.__right_shift(word, 10)

    def __cs0(self, word: int) -> int:
        return self.__right_rotate(word, 2) ^ self.__right_rotate(word, 13) ^ self.__right_rotate(word, 22)

    def __cs1(self, word: int) -> int:
        return self.__right_rotate(word, 6) ^ self.__right_rotate(word, 11) ^ self.__right_rotate(word, 25)


def show_binary(blob: bytearray, separation: str = ' ', bytes_split: int = 8) -> None:
    """ Auxiliar function used to debug intermediate steps """
    for i, digit in enumerate(blob):
        print(format(digit, '08b'), end=separation)
        if (i + 1) % bytes_split == 0:
            print('')
    print('')


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
group.add_argument('-t', '--text', help='Text to hash')
group.add_argument('-f', '--file', help='File to hash')
args = parser.parse_args()
if args.file is None:
    text = args.text
elif args.text is None:
    with open(args.file) as f:
        text = f.read().strip()
sha256 = SHA256()
digest = sha256.hash(text)
digest2 = hashlib.sha256(text.encode('utf-8')).hexdigest()
print('Digest:', digest)
assert(digest == digest2)
