# Crypto CTF 2024
##  Nabat | Medium | 159 pts

Task description:

```
Nabat is a cryptographic challenge that explores the representation of polynomials within a specific polynomial ring structure.

nc 02.cr.yp.toc.tf 37771
nc 00.cr.yp.toc.tf 37771

Note: The challenge SageMath script is updated, please redownload it.
```

Attachments:

```python
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
```

## Solution

What we need to do is to find a polynomial such that:

- it's coefficients are in $(-1, 0, 1)$
- it's degree is $d \ge 2 \ln(N) - 1$, where $N$ is the challenge number and $N \in (2^i, 2^{i+1})$
- The amount of zeros among the coefficients is $\ge \frac{2}{3} d -3 $
- $f(x) = N \pmod{x^2 + x + 2}$

### Sound's like an LLL task, but I did it old way.

First, let's address the last condition. Let's consider a polynomial $g(x) = b_0 + b_1 * x + ... + b_{d-2} * x^{d-2}$

We know that $f(x) = g(x) * (x^2 + x + 2) + N$, also we know that the coefficients of $f(x)$ are all in $(-1, 0, 1)$. Let's take a look at the resulting polynomial:


$f(x) = (2*b_0 + N) + x * (b_0 + 2 * b_1) + x^2 * (b_0 + b_1 + 2 * b_2) + x^3 * (b_1 + b_2 + 2 * b_3) + ... + x^{d - 2} * (b_{d - 4} + b_{d-3} + 2 * b_{d-2}) + x^{d-1}) * (b_{d-3} + 2 * b_{d-2}) + x^d * b_d$

----
We have the following conditions:

$2 * b_0 + N \in (-1, 0, 1)$

$b_0 + 2 * b_1 \in (-1, 0, 1)$

$b_0 + b_1 + 2 * b_2 \in (-1, 0, 1)$

...

$b_{d-4} + b_{d-3} + 2 * b_{d-2} \in (-1, 0, 1)$

$b_{d - 3} + b_{d - 2} \in (-1, 0, 1)$

$b_{d-2} \in (-1, 1)$

----


So I just wrote a recursive algorithm that searches for such a polynomial. In the final round it checks for the other conditions + last two rows in the above list to be true and spits out the solution. 


Also, since we start from the zero's coefficient, we can add an optimization.

for the first one: if $N$ is even then the whole sum have to be even, hence the only possible value would be 0, otherwise (-1, 1).

Same for the other ones.


```python
x = var("x")
R = PolynomialRing(ZZ, x)
g = R(x**2 + x + 2)
```


```python
def find_poly(beta, cursor, n, d):
    if cursor == d - 1:
        assert len(beta) == d - 1

        if (beta[-1] + beta[-2] not in [-1, 0, 1] or beta[-1] not in [-1, 0, 1]): # last two rows
            return None

        f1 = R(beta)
        f2 = f1 * g + n

        d1 = f2.degree()
        if f2.list().count(0) < 2 * d1 // 3 - 3: # third condition
            return None

        print("WIN")
        return f2

    if cursor == 0:   # f_0 
        if n & 1 == 0:
            beta0 = - n // 2
            res = find_poly([beta0], 1, n, d)
            if res is not None:
                return res
        else:
            for beta0 in [(-1 - n)//2, (1 - n) // 2]:
                res = find_poly([beta0], 1, n, d)
                if res is not None:
                    return res
        return None

    if cursor == 1:  # f_1
        beta0 = beta[-1]
        if beta0 & 1 == 0:
            beta1 = - beta0 // 2
            res = find_poly(beta + [beta1], 2, n, d)
            if res is not None:
                return res
        else:
            for beta1 in [(-1 - beta0)//2, (1-beta0)//2]:
                res = find_poly(beta + [beta1], 2, n, d)
                if res is not None:
                    return res
        return None

    beta_t = beta[-2] + beta[-1] # f_2 - f_{d}
    if beta_t & 1 == 0:
        beta1 = -beta_t // 2
        res = find_poly(beta + [beta1], cursor + 1, n, d)
        if res is not None:
            return res
    else:
        for beta1 in [(-1 - beta_t)//2,  (1 - beta_t)//2]:
            res = find_poly(beta + [beta1], cursor + 1, n, d)
            if res is not None:
                return res
    return None
```


```python
from pwn import remote
import re
host, port = "02.cr.yp.toc.tf", 37771
r = remote(host, port)
print(r.recvline().decode("utf-8"))
print(r.recvline().decode("utf-8"))
print(r.recvline().decode("utf-8"))
print(r.recvline().decode("utf-8"))
```

    [x] Opening connection to 02.cr.yp.toc.tf on port 37771
    [x] Opening connection to 02.cr.yp.toc.tf on port 37771: Trying 91.107.157.58
    [+] Opening connection to 02.cr.yp.toc.tf on port 37771: Done
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    
    ┃ Welcome to the NABAT challenge, your mission is to validate the main ┃
    
    ┃ check function in the provided system, Try your best to find flag :) ┃
    
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    



```python
for _ in range(1, 12):
    print(r.recvline().decode("utf-8"))
    n = int(re.findall(r'n = (.*),', r.recvline().decode())[0])
    print(f"{n = }")
    
    v = int(2 * log(n) - 1) # the lower bound on the resulting degree
    
    for d in range(max(v, 3), 100): # try to find the fitting degree
        print(d, end=", ")
        res = find_poly([], 0, n, d)
        if res is not None:
            break
    print(res)
    r.sendline(str(res).encode())
    
print(r.recvline().decode('utf-8'))
```

    ┃ Send a polynomial that satisfies the check function for each given `n'.
    
    n = 4
    3, WIN
    x^3 - x^2
    ┃ You have successfully passed step 1. Please proceed to the next step :)
    
    n = 5
    3, WIN
    x^3 - x^2 + 1
    ┃ You have successfully passed step 2. Please proceed to the next step :)
    
    n = 14
    4, 5, 6, WIN
    x^6 - x^5 + x^4 + x^3 - x^2 + x
    ┃ You have successfully passed step 3. Please proceed to the next step :)
    
    n = 25
    5, 6, 7, 8, WIN
    -x^8 + x^7 + x^6 - x^3 - x^2 - x - 1
    ┃ You have successfully passed step 4. Please proceed to the next step :)
    
    n = 38
    6, 7, 8, 9, 10, WIN
    x^10 - x^8 - x^7 - x
    ┃ You have successfully passed step 5. Please proceed to the next step :)
    
    n = 102
    8, 9, 10, 11, 12, WIN
    -x^12 - x^11 + x^10 + x^9 - x^8 - x^7 + x^6 - x
    ┃ You have successfully passed step 6. Please proceed to the next step :)
    
    n = 140
    8, 9, 10, 11, 12, 13, WIN
    x^13 - x^11 + x^10 - x^9 - x^7 - x^6 - x^4 - x^2
    ┃ You have successfully passed step 7. Please proceed to the next step :)
    
    n = 452
    11, 12, 13, 14, 15, 16, WIN
    x^16 - x^15 + x^13 - x^6 - x^5 - x^4 - x^3 - x^2
    ┃ You have successfully passed step 8. Please proceed to the next step :)
    
    n = 793
    12, 13, 14, 15, 16, 17, 18, WIN
    -x^18 + x^16 + x^13 + x^8 - x^6 - x^3 - x^2 - x - 1
    ┃ You have successfully passed step 9. Please proceed to the next step :)
    
    n = 1484
    13, 14, 15, 16, 17, 18, 19, 20, WIN
    x^20 + x^19 - x^18 - x^17 + x^10 - x^9 - x^8 - x^7 - x^4 - x^2
    ┃ You have successfully passed step 10. Please proceed to the next step :)
    
    n = 3805
    15, 16, 17, 18, 19, 20, 21, 22, 23, WIN
    x^23 - x^21 - x^20 + x^16 - x^15 - x^11 + x^9 - x^8 - x^7 - x^2 + 1
    ┃ Congrats, you got the flag: b'CCTF{0p71M!5TiC_rEpR3SenT4t!0n_Of_n_8Y_Frobenius!}'
    


### Sidenote on the flag meaning

This is a reference to an optimized point multiplication due to frobenious polynomial. 
On elliptic curves over $F_{p^d}$ we have the following is true:

$e(x^{p^2}, y^{p^2}) - a * e(x^{p}, y^{p}) + p * e(x, y) = 0$ where `a` is the trace of Frobenius of an elliptic curve

As you can see we can represent multiplication by $p$ in terms of kind of simple operation of exponentiation.

For Koblitz curve $y^2 + xy = x^3 + 1$ over $\mathbb{F}_{2}$, $a = -1$ so the resulting polynomial is $x^2 + x + 2$ and to perform multiplication by $n$ we need to represent $n$ in terms of roots of this polynomial. This is exactly it.

For example:


```python
v1, v2 = (x^2 + x + 2).roots()
v1
```




    (-1/2*I*sqrt(7) - 1/2, 1)




```python
tau = v1[0]

(x^23 - x^21 - x^20 + x^16 - x^15 - x^11 + x^9 - x^8 - x^7 - x^2 + 1)(x=tau).factor()
```




    3805



It's optimistic, because we don't need to use any extra point multiplications and also it takes much less addition operations than other methods.

Btw there're algorithms that solve this problem without recursion.


```python
def find_decomposition(n):
    i = 0
    n0 = n
    n1 = 0
    vs = []
    while n0 != 0 or n1 != 0:
        if n0 % 2 == 1:
            vi = 2 - ((n0 - 2 * n1) % 4)
            n0 = n0 - vi
            vs.append(vi)
        else:
            vs.append(0)
        i += 1
        n0, n1 = n1 - n0 // 2, -n0//2
    return vs

f = R(find_decomposition(3805))
f
```




    x^26 - x^23 + x^21 - x^19 + x^17 + x^14 - x^12 - x^10 + x^7 - x^2 + 1




```python
f(x=tau).factor()
f.list().count(0) >= 2/3 * 26 - 3
```




    True




```python
from pwn import remote
import re
host, port = "02.cr.yp.toc.tf", 37771
r = remote(host, port)
(r.recvline().decode("utf-8"))
(r.recvline().decode("utf-8"))
(r.recvline().decode("utf-8"))
(r.recvline().decode("utf-8"))

for _ in range(1, 12):
    print(r.recvline().decode("utf-8"))
    n = int(re.findall(r'n = (.*),', r.recvline().decode())[0])
    print(f"{n = }")
    f = find_decomposition(n)
    r.sendline(str(R(f)).encode())
    
print(r.recvline().decode('utf-8'))
```

    [x] Opening connection to 02.cr.yp.toc.tf on port 37771
    [x] Opening connection to 02.cr.yp.toc.tf on port 37771: Trying 91.107.157.58
    [+] Opening connection to 02.cr.yp.toc.tf on port 37771: Done
    ┃ Send a polynomial that satisfies the check function for each given `n'.
    
    n = 3
    ┃ You have successfully passed step 1. Please proceed to the next step :)
    
    n = 7
    ┃ You have successfully passed step 2. Please proceed to the next step :)
    
    n = 16
    ┃ You have successfully passed step 3. Please proceed to the next step :)
    
    n = 27
    ┃ You have successfully passed step 4. Please proceed to the next step :)
    
    n = 39
    ┃ You have successfully passed step 5. Please proceed to the next step :)
    
    n = 115
    ┃ You have successfully passed step 6. Please proceed to the next step :)
    
    n = 174
    ┃ You have successfully passed step 7. Please proceed to the next step :)
    
    n = 357
    ┃ You have successfully passed step 8. Please proceed to the next step :)
    
    n = 539
    ┃ You have successfully passed step 9. Please proceed to the next step :)
    
    n = 1100
    ┃ You have successfully passed step 10. Please proceed to the next step :)
    
    n = 3413
    ┃ Congrats, you got the flag: b'CCTF{0p71M!5TiC_rEpR3SenT4t!0n_Of_n_8Y_Frobenius!}'
    

