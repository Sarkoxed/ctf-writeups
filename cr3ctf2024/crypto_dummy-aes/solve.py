from pwn import remote
import re
from aes import InvSbox, Rcon, Sbox
from itertools import product

def text2matrix(text):
    matrix = []
    for i in range(16):
        byte = (text >> (8 * (15 - i))) & 0xFF
        if i % 4 == 0:
            matrix.append([byte])
        else:
            matrix[i // 4].append(byte)
    return matrix


def matrix2text(matrix):
    text = 0
    for i in range(4):
        for j in range(4):
            text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
    return text

host, port = "localhost", 1337
host, port = "1337.sb", 20003

r = remote(host, port)

identity = [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]]
negidentity = [[255, 0, 0, 0], [0, 255, 0, 0], [0, 0, 255, 0], [0, 0, 0, 255]]
tridentity = [[3, 0, 0, 0], [0, 3, 0, 0], [0, 0, 3, 0], [0, 0, 0, 3]]

r.recvline()

ms = []
for resm in [identity, negidentity, tridentity]:
    for _ in range(4):
        print(r.recvline())

    r.sendline(b'1')
    r.sendline((b'\x00' * 15).hex().encode())
    r.sendline(matrix2text(resm).to_bytes(16, 'big').hex().encode())
    m = r.recvline().decode()
    print(m.encode())
    m = int(re.findall(r'Enter your matrix\(hex\): (.*)\n', m)[0])
    ms.append(text2matrix(m))

for _ in range(4):
    print(r.recvline())

r.sendline(b'2')
r.sendline(matrix2text(identity).to_bytes(16, 'big').hex().encode())
m = r.recvline().decode()
enc_flag = int(re.findall(r'Enter your matrix\(hex\): (.*)\n', m)[0])
r.close()

possible_last_round_key = []
for i, j in product([0, 1, 2, 3], repeat=2):
    tmp = []
    for k in range(256):
        t1 = InvSbox[ms[0][i][j] ^ k]
        t2 = InvSbox[ms[1][i][j] ^ k]
        t3 = InvSbox[ms[2][i][j] ^ k]
        if t1 == 256 - t2 and (3 * t1) % 256 == t3:
            tmp.append(k)
    print(tmp)
    possible_last_round_key.append(tmp)

def inv_shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

from Crypto.Cipher import AES
for k in product(*possible_last_round_key):
    print(k)
    l_k = [[k[j + 4 * i] for j in range(4)] for i in range(4)]
    round_keys = [[0] * 4 for _ in range(4 * 10)] + l_k
    
    for i in reversed(range(4, 4 * 11)):
        if i % 4 == 0:
            for j in reversed(range(1, 4)):
                byte = round_keys[i][j]
                round_keys[i - 4][j] = byte ^ Sbox[round_keys[i-1][(j +1) % 4]]

            byte = round_keys[i][0]
            round_keys[i - 4][0] = byte ^ Sbox[round_keys[i - 1][1]] ^ Rcon[i // 4]
        else:
            for j in reversed(range(4)):
                byte = round_keys[i][j]
                round_keys[i - 4][j] = byte ^ round_keys[i - 1][j]

    master_key = round_keys[:4]
    master_key = b"".join(bytes(x) for x in master_key)
    cipher = AES.new(key=master_key, mode=AES.MODE_ECB)
    print(cipher.decrypt(enc_flag.to_bytes(48, 'big')))
