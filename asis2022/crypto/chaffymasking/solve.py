from pwn import * 
from IVK import IVK
import numpy as np


def pad(inp, length):
    result = inp + os.urandom(length - len(inp))
    return result


def byte_xor(a, b):
    return bytes(_a ^ _b for _a, _b in zip(a, b))


def chaffy_mask(masked_fl, salt, LTC, m, n):
    q = n**2
    half1_salt = salt[: m // 8]
    half2_salt = salt[m // 8 :]

    half1_binStr = "{:08b}".format(int(half1_salt.hex(), 16))
    half2_binStr = "{:08b}".format(int(half2_salt.hex(), 16))

    vec_1 = np.array(list(half1_binStr), dtype=int)
    vec_1 = np.reshape(vec_1, (m, 1))
    vec_2 = np.array(list(half2_binStr), dtype=int)
    vec_2 = np.reshape(vec_2, (m, 1))

    out_1 = LTC.dot(vec_1) % q
    out_2 = LTC.dot(vec_2) % q

    flag_vector = np.array([ord(i) for i in masked_fl])
    flag_vector = np.reshape(flag_vector, (n, 1))
    masked_flag = (flag_vector ^ out_1 ^ out_2) % 256
    masked_flag = np.reshape(masked_flag, (n,))
    masked_flag = "".join([hex(_)[2:].zfill(2) for _ in masked_flag])
    return masked_flag.encode("utf-8")


m, n = 512, 64

LTC = np.zeros([n, m], dtype=(int))
LTC[0, :] = IVK

for i in range(1, n):
    for j in range(m // n + 1):
        LTC[i, j * n : (j + 1) * n] = np.roll(IVK[j * n : (j + 1) * n], i)

r = remote("65.21.255.31", 31377)

from Crypto.Util.number import bytes_to_long, long_to_bytes
import re

salt = long_to_bytes(int('1'+'0'*511 + '1' + '0' * 510 + '1'))
r.recvuntil(b"Give me your salt:")
r.sendline(salt)
m = r.recvuntil(b"Give me your salt").decode()
print(m)
print(re.findall(r'masked_flag = (*.)', m))


