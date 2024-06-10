# Crypto CTF 2024
##  Imen | Hard | 194 pts

Task description:

```
Imen presents a challenging task involving a novel and creative cryptosystem, inviting you to attempt to break it and obtain the flag.

nc 03.cr.yp.toc.tf 31117
nc 00.cr.yp.toc.tf 31117
nc 01.cr.yp.toc.tf 31117

```

Attachments:

```python
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
````

## Solution

Here we have an oracle task. This code simply generates `12 + level` random 3x3 matrices over `F_p`. However the resulting matrices are then scaled down by taking the remainder by a small number. 

Then they generate a random permutation and multiply these matrices in the new order. 

The thing here is that the prime is growing each level, such that matrix multiplication doesn't overflow and stays inside integers region. 

Thus to recover the permutation we can simply iterate over the still unused matrices and check the following:

Sps we have this permutation - $M = A_{i_1} * A_{i_2} * ... * A_{i_k}$

Then multiplying by  $A_{i_k}^{-1}$ from the right hand side will not affect the "integerness" of the whole structure. Matrices will simply collapse. However it's highly unlikely that the matrix will stay over integers if we multiply by some other inverse.


```python
from pwn import remote

host, port = "03.cr.yp.toc.tf", 31117
r = remote(host, port)

for _ in range(4):
    print(r.recvline().decode("utf-8"))
```

    [x] Opening connection to 03.cr.yp.toc.tf on port 31117
    [x] Opening connection to 03.cr.yp.toc.tf on port 31117: Trying 91.107.243.125
    [+] Opening connection to 03.cr.yp.toc.tf on port 31117: Done
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    
    ┃ Hi all, now it's time to solve a new and creative IMEN challenge     ┃
    
    ┃ In each step, try to find the unknown permutation to get the flag!   ┃
    
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    


Here're several useful functions to retrieve the values from the oracle


```python
def get_matrices(r, round_):
    for _ in range(5):
        r.recvline()
    r.sendline(b'g')
    
    mts = []
    for _ in range(12 + round_):
        t1 = r.recvline().decode('utf-8')[1:].strip("[  ]\n").split()
        t2 = r.recvline().decode('utf-8').strip("[  ]\n").split()
        t3 = r.recvline().decode('utf-8').strip("[  ]\n").split()
        rm = [[int(x) for x in t] for t in [t1, t2, t3]]
        mts.append(Matrix(rm))
    return mts

def get_M(r):
    for _ in range(5):
        r.recvline()
    r.sendline(b'p')
        
    t1 = r.recvline().decode('utf-8')[1:].strip("M = [  ]\n").split()
    t2 = r.recvline().decode('utf-8').strip("[  ]\n").split()
    t3 = r.recvline().decode('utf-8').strip("[  ]\n").split()
    rm = [[int(x) for x in t] for t in [t1, t2, t3]]
    return Matrix(rm)

def submit(r, p):
    for _ in range(5):
        r.recvline()
    r.sendline(b's')
    r.sendline(str(p).strip('[]').encode())
    f = r.recvline()
    return f.decode('utf-8')
```

We can't simply iterate over all the permutations and choose the first one that returns the correct matrix. Sometimes it can accidentally collapse. Or the determinant of the matrix is 1. A lot of stuff can happen, so that's how we avoid the false positives.


```python
def get_permutation(ms, tmpm, perm):
    print(perm)
    if len(perm) == len(ms):
        if tmpm.is_one():  # the final check that the product became an identity matrix
            return perm
        return None

    for i in range(len(ms)):
        if i not in perm:
            t1 = ms[i]**-1
            m1 = tmpm * t1
            if (all(x.is_integer() for y in m1 for x in y)):
                res = get_permutation(ms, m1, [i] + perm)
                if res is not None:
                    return res
    return None
```


```python
for round_ in range(12):
    ms = get_matrices(r, round_)
    M = get_M(r)
    
    perm = get_permutation(ms, Matrix(M), [])
    assert perm is not None
   
    assert prod(ms[i] for i in perm) == M
    print(submit(r, perm))
```

    []
    [2]
    [6, 2]
    [1, 6, 2]
    [3, 1, 6, 2]
    [11, 3, 1, 6, 2]
    [8, 11, 3, 1, 6, 2]
    [5, 8, 11, 3, 1, 6, 2]
    [10, 5, 8, 11, 3, 1, 6, 2]
    [4, 10, 5, 8, 11, 3, 1, 6, 2]
    [7, 4, 10, 5, 8, 11, 3, 1, 6, 2]
    [0, 7, 4, 10, 5, 8, 11, 3, 1, 6, 2]
    [9, 0, 7, 4, 10, 5, 8, 11, 3, 1, 6, 2]
    ┃ gj, you got the 0, try the next level now!
    
    []
    [3]
    [11, 3]
    [12, 11, 3]
    [8, 12, 11, 3]
    [10, 8, 12, 11, 3]
    [1, 10, 8, 12, 11, 3]
    [6, 1, 10, 8, 12, 11, 3]
    [9, 6, 1, 10, 8, 12, 11, 3]
    [2, 9, 6, 1, 10, 8, 12, 11, 3]
    [5, 2, 9, 6, 1, 10, 8, 12, 11, 3]
    [0, 5, 2, 9, 6, 1, 10, 8, 12, 11, 3]
    [4, 0, 5, 2, 9, 6, 1, 10, 8, 12, 11, 3]
    [7, 4, 0, 5, 2, 9, 6, 1, 10, 8, 12, 11, 3]
    ┃ gj, you got the 1, try the next level now!
    
    []
    [0]
    [4]
    [3, 4]
    [0, 3, 4]
    [7, 0, 3, 4]
    [11, 7, 0, 3, 4]
    [11, 0, 3, 4]
    [7, 11, 0, 3, 4]
    [13, 11, 0, 3, 4]
    [2, 13, 11, 0, 3, 4]
    [7, 2, 13, 11, 0, 3, 4]
    [9, 2, 13, 11, 0, 3, 4]
    [1, 9, 2, 13, 11, 0, 3, 4]
    [7, 1, 9, 2, 13, 11, 0, 3, 4]
    [10, 1, 9, 2, 13, 11, 0, 3, 4]
    [12, 10, 1, 9, 2, 13, 11, 0, 3, 4]
    [8, 12, 10, 1, 9, 2, 13, 11, 0, 3, 4]
    [7, 8, 12, 10, 1, 9, 2, 13, 11, 0, 3, 4]
    [5, 7, 8, 12, 10, 1, 9, 2, 13, 11, 0, 3, 4]
    [6, 5, 7, 8, 12, 10, 1, 9, 2, 13, 11, 0, 3, 4]
    ┃ gj, you got the 2, try the next level now!
    
    []
    [6]
    [14, 6]
    [12, 14, 6]
    [2, 12, 14, 6]
    [0, 2, 12, 14, 6]
    [3, 0, 2, 12, 14, 6]
    [5, 3, 0, 2, 12, 14, 6]
    [4, 5, 3, 0, 2, 12, 14, 6]
    [7, 4, 5, 3, 0, 2, 12, 14, 6]
    [13, 7, 4, 5, 3, 0, 2, 12, 14, 6]
    [8, 13, 7, 4, 5, 3, 0, 2, 12, 14, 6]
    [9, 8, 13, 7, 4, 5, 3, 0, 2, 12, 14, 6]
    [11, 9, 8, 13, 7, 4, 5, 3, 0, 2, 12, 14, 6]
    [1, 11, 9, 8, 13, 7, 4, 5, 3, 0, 2, 12, 14, 6]
    [10, 1, 11, 9, 8, 13, 7, 4, 5, 3, 0, 2, 12, 14, 6]
    ┃ gj, you got the 3, try the next level now!
    
    []
    [14]
    [3, 14]
    [2, 3, 14]
    [0, 2, 3, 14]
    [7, 0, 2, 3, 14]
    [4, 7, 0, 2, 3, 14]
    [10, 4, 7, 0, 2, 3, 14]
    [11, 10, 4, 7, 0, 2, 3, 14]
    [13, 11, 10, 4, 7, 0, 2, 3, 14]
    [5, 13, 11, 10, 4, 7, 0, 2, 3, 14]
    [8, 5, 13, 11, 10, 4, 7, 0, 2, 3, 14]
    [15, 8, 5, 13, 11, 10, 4, 7, 0, 2, 3, 14]
    [12, 15, 8, 5, 13, 11, 10, 4, 7, 0, 2, 3, 14]
    [6, 12, 15, 8, 5, 13, 11, 10, 4, 7, 0, 2, 3, 14]
    [1, 6, 12, 15, 8, 5, 13, 11, 10, 4, 7, 0, 2, 3, 14]
    [9, 1, 6, 12, 15, 8, 5, 13, 11, 10, 4, 7, 0, 2, 3, 14]
    ┃ gj, you got the 4, try the next level now!
    
    []
    [8]
    [4, 8]
    [12, 8]
    [4, 12, 8]
    [13, 4, 12, 8]
    [10, 13, 4, 12, 8]
    [0, 10, 13, 4, 12, 8]
    [15, 0, 10, 13, 4, 12, 8]
    [2, 15, 0, 10, 13, 4, 12, 8]
    [14, 2, 15, 0, 10, 13, 4, 12, 8]
    [3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    [5, 3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    [7, 5, 3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    [11, 7, 5, 3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    [1, 11, 7, 5, 3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    [16, 1, 11, 7, 5, 3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    [9, 16, 1, 11, 7, 5, 3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    [6, 9, 16, 1, 11, 7, 5, 3, 14, 2, 15, 0, 10, 13, 4, 12, 8]
    ┃ gj, you got the 5, try the next level now!
    
    []
    [4]
    [5]
    [10, 5]
    [9, 10, 5]
    [16, 9, 10, 5]
    [0, 16, 9, 10, 5]
    [2, 0, 16, 9, 10, 5]
    [1, 2, 0, 16, 9, 10, 5]
    [4, 2, 0, 16, 9, 10, 5]
    [13, 4, 2, 0, 16, 9, 10, 5]
    [1, 13, 4, 2, 0, 16, 9, 10, 5]
    [11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [3, 7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [8, 3, 7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [14, 8, 3, 7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [6, 14, 8, 3, 7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [12, 6, 14, 8, 3, 7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [15, 12, 6, 14, 8, 3, 7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    [17, 15, 12, 6, 14, 8, 3, 7, 11, 1, 13, 4, 2, 0, 16, 9, 10, 5]
    ┃ gj, you got the 6, try the next level now!
    
    []
    [1]
    [9, 1]
    [15, 9, 1]
    [5, 15, 9, 1]
    [14, 5, 15, 9, 1]
    [13, 14, 5, 15, 9, 1]
    [16, 13, 14, 5, 15, 9, 1]
    [7, 16, 13, 14, 5, 15, 9, 1]
    [10, 7, 16, 13, 14, 5, 15, 9, 1]
    [12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [0, 2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [3, 0, 2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [4, 3, 0, 2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [18, 4, 3, 0, 2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [6, 18, 4, 3, 0, 2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [17, 6, 18, 4, 3, 0, 2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    [8, 17, 6, 18, 4, 3, 0, 2, 11, 12, 10, 7, 16, 13, 14, 5, 15, 9, 1]
    ┃ gj, you got the 7, try the next level now!
    
    []
    [4]
    [17, 4]
    [19, 17, 4]
    [9, 19, 17, 4]
    [16, 19, 17, 4]
    [9, 16, 19, 17, 4]
    [10, 9, 16, 19, 17, 4]
    [18, 10, 9, 16, 19, 17, 4]
    [2, 18, 10, 9, 16, 19, 17, 4]
    [13, 2, 18, 10, 9, 16, 19, 17, 4]
    [12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [0, 6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [15, 0, 6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [14, 15, 0, 6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [1, 14, 15, 0, 6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [11, 1, 14, 15, 0, 6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [5, 11, 1, 14, 15, 0, 6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    [7, 5, 11, 1, 14, 15, 0, 6, 3, 8, 12, 13, 2, 18, 10, 9, 16, 19, 17, 4]
    ┃ gj, you got the 8, try the next level now!
    
    []
    [9]
    [10, 9]
    [17, 9]
    [2, 17, 9]
    [15, 2, 17, 9]
    [5, 15, 2, 17, 9]
    [11, 5, 15, 2, 17, 9]
    [0, 11, 5, 15, 2, 17, 9]
    [16, 0, 11, 5, 15, 2, 17, 9]
    [4, 16, 0, 11, 5, 15, 2, 17, 9]
    [6, 4, 16, 0, 11, 5, 15, 2, 17, 9]
    [18, 16, 0, 11, 5, 15, 2, 17, 9]
    [13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [7, 20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [12, 7, 20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [14, 12, 7, 20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [10, 14, 12, 7, 20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [19, 10, 14, 12, 7, 20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [3, 19, 10, 14, 12, 7, 20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    [4, 3, 19, 10, 14, 12, 7, 20, 6, 1, 8, 13, 18, 16, 0, 11, 5, 15, 2, 17, 9]
    ┃ gj, you got the 9, try the next level now!
    
    []
    [19]
    [7, 19]
    [4, 7, 19]
    [3, 4, 7, 19]
    [20, 3, 4, 7, 19]
    [9, 20, 3, 4, 7, 19]
    [21, 9, 20, 3, 4, 7, 19]
    [11, 21, 9, 20, 3, 4, 7, 19]
    [18, 11, 21, 9, 20, 3, 4, 7, 19]
    [14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [1, 13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [0, 1, 13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [6, 0, 1, 13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [17, 6, 0, 1, 13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [5, 17, 6, 0, 1, 13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [8, 5, 17, 6, 0, 1, 13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    [15, 8, 5, 17, 6, 0, 1, 13, 12, 16, 2, 10, 14, 18, 11, 21, 9, 20, 3, 4, 7, 19]
    ┃ gj, you got the 10, try the next level now!
    
    []
    [20]
    [22]
    [11, 22]
    [1, 11, 22]
    [3, 1, 11, 22]
    [5, 3, 1, 11, 22]
    [4, 5, 3, 1, 11, 22]
    [21, 4, 5, 3, 1, 11, 22]
    [7, 21, 4, 5, 3, 1, 11, 22]
    [18, 7, 21, 4, 5, 3, 1, 11, 22]
    [6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [13, 16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [12, 13, 16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [19, 12, 13, 16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [14, 19, 12, 13, 16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [20, 14, 19, 12, 13, 16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [8, 20, 14, 19, 12, 13, 16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    [0, 8, 20, 14, 19, 12, 13, 16, 2, 15, 9, 17, 10, 6, 18, 7, 21, 4, 5, 3, 1, 11, 22]
    ┃ Congratulation! You got the flag: b'CCTF{c4N_y0U_3fF1c!En7lY_rEc0v3Re_tH3_0rD3R_of_M4tR1x_PrODuC7S?}'
    

