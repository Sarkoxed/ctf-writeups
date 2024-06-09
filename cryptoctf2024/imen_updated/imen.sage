#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
load('secret.sage')

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

def genimen(k, p, _B):
	while True:
		A = random_matrix(GF(p), k)
		for i in range(k):
			for j in range(k):
				A[i, j] = int(A[i, j]) % (_B + 1)
		if det(A) != 0:
			return A

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "Hi all, now it's time to solve a new and creative IMEN challenge    ", border)
	pr(border, "In each step, try to find the unknown permutation to get the flag!  ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit, step = 128, 12
	for level in range(step):
		k, l, p, B = 3, 12 + level, getPrime(nbit), 14 + (level + 1)
		nbit = int((k * l) ** B).bit_length() + 5 
		while True:
			A = [genimen(k, p, B) for _ in range(l)]
			L = list(range(l))
			shuffle(L)
			M = prod([A[_] for _ in L])
			if check(A, M): break
		while True:
			pr(f"| Options: \n|\t[G]et {l} matrices \n|\t[P]roduct of matrices \n|\t[S]ubmit the permutation \n|\t[Q]uit")
			ans = sc().decode().lower().strip()
			if ans == 'g':
				for i in range(l):
					pr(border, f'{A[i]}')
			elif ans == 'p':
				pr(border, f'M = {M}')
			elif ans == 's':
				_p = sc().decode()
				try:
					_p = [int(_) for _ in _p.split(',')]
				except:
					die(border, f'Your permutation is not valid!')
				if _p == L:
					if level == step - 1:
						die(border, f'Congratulation! You got the flag: {flag}')
					else:
						pr(border, f'gj, you got the {level}, try the next level now!')
						break
				else:
					die(border, f'The permutation is not corr3ct! Bye!!')
			elif ans == 'q':
				die(border, 'Quitting...')
			else:
				die(border, 'You should select valid choice!')

if __name__ == '__main__':
	main()