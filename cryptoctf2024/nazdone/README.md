# Crypto CTF 2024
##  Nazdone | Medium | 122 pts

Task description:

```
Nazdone is a cryptographic exercise focused on the practical challenges of generating random prime numbers for real-world applications.
```

Attachments:

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from random import *
from secret import params, flag

def sol(m, a, z):
	p = m * (a - 1) % 2 + 1
	while True:
		R = list(range(1, a))
		shuffle(R)
		for r in R[:z]:
			p += getRandomRange(0, 2) * m ** r
		if isPrime(p):
			return p
		else:
			p = m * (a - 1) % 2 + 1


p, q, r = [sol(*params) for _ in '007']
n = p * q * r
m = bytes_to_long(flag)
c = pow(m, params[0] ** 3 + params[2] - 2, n)
print(f'n = {n}')
print(f'c = {c}')
```

`output.txt`:


```python
n = 301929748923678449872944933611657670834216889867340028357609265175830693931365828840717548752313862343315133541384709574659039910206634528428504034051556622114290811586746168354731258756502196637977942743110508997919976400864419640496894428180120687863921269087080600917900477624095004141559042793509244689248253036809126205146653922738685595903222471152317095497914809983689734189245440774658145462867680027337
c = 104375152140523502741159687674899095271676058870899569351687154311685938980840028326701029233383897490722759532494438442871187152038720886122756131781086198384270569105043114469786514257765392820254951665751573388426239366215033932234329514161827069071792449190823827669673064646681779764841034307000600929149689291216313319444583032339045277433847691961234044840927155960887984372868669401051358701522484473320
```

## Solution

Here we have three prime numbers, that are of the form $p = \displaystyle\sum_{i=0}^z \alpha_i * m^i$, where $\alpha_i \in (0, 1)$

This helps. When we do the product of these `polynomials`, since the coefficient are `0-1` the coefficients do not contribute to the power shift. They are kind of small. That's why we can factor the `polynomial` instead of the number.

But first we should find the base. I tried to come up with the conditions for the base, but the simplest one is to straight check that the polynomial is factorizable


```python
def rebase(n, b):
    if n < b:
        return [n]
    else:
        return [n % b] + rebase(n//b, b)
```


```python
x = var('x')
P = PolynomialRing(ZZ, x)
for m in range(3, 200):
     tmp = rebase(n, m)
     k1 = factor(P(tmp))
     if len(k1) >= 3:
         print(m, k1)
```

    19 (x^106 + x^81 + x^77 + x^59 + x^47 + x^42 + x^22 + x^11 + x^7 + 2) * (x^107 + x^88 + x^51 + x^43 + x^37 + x^36 + x^35 + x^18 + x^14 + 2) * (x^108 + x^93 + x^74 + x^64 + x^31 + 2)



```python
t1, t2, t3 = [x[0] for x in factor(P(rebase(n, 19)))]
p, q, r = t1(x=19), t2(x=19), t3(x=19)
assert p * q * r == n
```

We still don't know `z` but we know it's lower bound which is the maximum of the number of monomials in `t's`


```python
(len(t1.coefficients()), len(t2.coefficients()), len(t3.coefficients()))
```




    (10, 10, 6)




```python
for z in range(10, 20):
    tmp_pow = 19**3 + z - 2
    try:
        p1 = pow(tmp_pow, -1, p - 1)
        p2 = pow(tmp_pow, -1, q - 1)
        p3 = pow(tmp_pow, -1, r - 1)

        m1 = pow(c, p1, p)
        m2 = pow(c, p2, q)
        m3 = pow(c, p3, r)
        res = crt([m1, m2, m3], [p, q, r])
        print(int(res).to_bytes(50, 'big'))
    except Exception as e:
        print(e)
        continue
```

    Inverse does not exist.
    Inverse does not exist.
    int too big to convert
    Inverse does not exist.
    b'\x00\x00\x00\x00\x00\x00\x00CCTF{nUmb3r5_1N_D!fFerEn7_8As35_4r3_n!cE!?}'
    Inverse does not exist.
    Inverse does not exist.
    Inverse does not exist.
    Inverse does not exist.
    Inverse does not exist.

