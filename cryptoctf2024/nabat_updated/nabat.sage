#!/usr/bin/env sage

import sys
from flag import flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc(): 
	return sys.stdin.buffer.readline()

def randstr(l):
	return ''.join([printable[randint(0, 90)] for _ in range(l)])

def check(f, l):
	R = PolynomialRing(ZZ, 'x')
	f, g = R(f), R(x^2 + x + 2)
	coefs = f.list()
	_b1 = all(abs(_) <= 1 for _ in coefs)
	_b2 = f.degree() + 1 - 2 * n(log(l)) >= 0
	_b3 = coefs.count(0) >= 2 * f.degree() // 3 - 3
	_b4 = (f - l) % g == 0
	if _b1 and _b2 and _b3 and _b4:
		return True
	return False

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "Welcome to the NABAT challenge, your mission is to validate the main", border)
	pr(border, "check function in the provided system, Try your best to find flag :)", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	step = 12
	R = PolynomialRing(ZZ, 'x')
	pr(border, f"Send a polynomial that satisfies the check function for each given `n'.")
	for i in range(1, step):
		n = randint(2**i, 2**(i + 1))
		pr(border, f"Your are in step {i} and n = {n}, please send the polynomial f:")
		_f = sc().decode()
		try:
			_f = R(_f)
		except:
			die(border, f"The polynomial you provided is is not valid!")
		_b = check(_f, n)
		if _b:
			if i == step - 1:
				die(border, f'Congrats, you got the flag: {flag}')
			else:
				pr(border, f'You have successfully passed step {i}. Please proceed to the next step :)')
		else:
			die(border, f"Your input does not meet the requirements!!!")

if __name__ == '__main__':
	main()