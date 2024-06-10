#!/usr/bin/python

import gmpy2
import math
import os
import sys
from Crypto.Util.number import getPrime
from random import randint


def get_prime(bits):
    return getPrime(bits)


def get_smooth_prime(bits, smoothness=16):
    p = 2
    p_factors = [p]
    while p.bit_length() < bits - 2 * smoothness:
        factor = get_prime(smoothness)
        p_factors.append(factor)
        p *= factor

    bitcnt = (bits - p.bit_length()) // 2
    print(bitcnt)

    while True:
        prime1 = get_prime(bitcnt)
        prime2 = get_prime(bitcnt)
        tmpp = p * prime1 * prime2
        if tmpp.bit_length() < bits:
            bitcnt += 1
            continue
        if tmpp.bit_length() > bits:
            bitcnt -= 1
            continue
        if gmpy2.is_prime(tmpp + 1):
            p_factors.append(prime1)
            p_factors.append(prime2)
            p = tmpp + 1
            break

    p_factors.sort()

    return (p, p_factors)


e = 0x10001

if __name__ == "__main__":
    n = int(input("n: "))
    p, p_factors = get_smooth_prime(n)
    print(f"{p, p_factors = }")
