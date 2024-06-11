#!/usr/bin/env sage

from Crypto.Util.number import *
from os import urandom
from flag import flag

def pad(m):
	m += b'\x8f' * (8 - len(m) % 8)
	return m

def duzly(m, C):
	ow, E = 0, [2**24 + 17, 2**24 + 3, 3, 2, 1, 0]
	for _ in range(6):
		ow += C[_] * pow(m, E[_], p)
	return ow % p

def pashan(msg):
	msg = pad(msg)
	pash, msg = b'', [msg[8*i:8*(i+1)] for i in range(len(msg) // 8)]
	for m in msg:
		_h = duzly(bytes_to_long(m), C).to_bytes(8, 'big')
		pash += _h
	return pash

p = 2**64 - 59
C = [1] + [randint(0, p) for _ in range(5)]
flag = urandom(getRandomRange(0, 110)) + flag + urandom(getRandomRange(0, 110))
_pash = pashan(flag)

f = open('_pash', 'wb')
f.write(str(C).encode() + b'\n')
f.write(_pash)
f.close()

f = open("flag_txt", 'wb')
f.write(flag)
f.close()
