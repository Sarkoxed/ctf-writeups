#!/usr/bin/env python3

from IVK import IVK

import numpy as np
import binascii
import os, sys
from flag import FLAG


def die(*args):
    pr(*args)
    quit()


def pr(*args):
    s = " ".join(map(str, args))
    sys.stdout.write(s + "\n")
    sys.stdout.flush()


def sc():
    return sys.stdin.buffer.readline()


def pad(inp, length):
    result = inp + os.urandom(length - len(inp))
    return result


def byte_xor(a, b):
    return bytes(_a ^ _b for _a, _b in zip(a, b))


def chaffy_mask(salt, LTC, m, n):
    q = n**2
    half1_salt = salt[: m // 8]
    half2_salt = salt[m // 8 :]
    xor_salts = int.from_bytes(byte_xor(half1_salt, half2_salt), "big")

    if xor_salts == 0:
        half1_salt = byte_xor(half1_salt, os.urandom(m))
    half1_binStr = "{:08b}".format(int(half1_salt.hex(), 16))
    if len(half1_binStr) < m:
        half1_binStr = "0" * (m - len(half1_binStr) % m) + half1_binStr
    half2_binStr = "{:08b}".format(int(half2_salt.hex(), 16))
    if len(half2_binStr) < m:
        half2_binStr = "0" * (m - len(half2_binStr) % m) + half2_binStr

    vec_1 = np.array(list(half1_binStr), dtype=int)
    vec_1 = np.reshape(vec_1, (m, 1))
    vec_2 = np.array(list(half2_binStr), dtype=int)
    vec_2 = np.reshape(vec_2, (m, 1))

    out_1 = LTC.dot(vec_1) % q
    out_2 = LTC.dot(vec_2) % q

    flag_vector = np.array([ord(i) for i in FLAG])
    flag_vector = np.reshape(flag_vector, (n, 1))
    masked_flag = (flag_vector ^ out_1 ^ out_2) % 256
    masked_flag = np.reshape(masked_flag, (n,))
    masked_flag = "".join([hex(_)[2:].zfill(2) for _ in masked_flag])
    return masked_flag.encode("utf-8")


def main():
    border = "|"
    pr(border * 72)
    pr(
        border,
        " Welcome to chaffymask combat, we implemented a masking method to   ",
        border,
    )
    pr(
        border,
        " hide our secret. Masking is done by your 1024 bit input salt. Also ",
        border,
    )
    pr(
        border,
        " I noticed that there is a flaw in my method. Can you abuse it and  ",
        border,
    )
    pr(
        border,
        " get the flag? In each step you should send salt and get the mask.  ",
        border,
    )
    pr(border * 72)

    m, n = 512, 64

    LTC = np.zeros([n, m], dtype=(int))
    LTC[0, :] = IVK

    for i in range(1, n):
        for j in range(m // n + 1):
            LTC[i, j * n : (j + 1) * n] = np.roll(IVK[j * n : (j + 1) * n], i)

    for _ in range(5):
        pr(border, "Give me your salt: ")
        SALT = sc()[:-1]
        SALT = pad(SALT, m // 4)
        MASKED_FLAG = chaffy_mask(SALT, LTC, m, n)
        pr(border, f"masked_flag = {MASKED_FLAG}")


if __name__ == "__main__":
    main()
