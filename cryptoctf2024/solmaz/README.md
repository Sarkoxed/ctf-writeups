# Crypto CTF 2024
##  Solmaz | Hard | 271 pts

Task description:

```
Solmaz has developed a simple and visually appealing cryptosystem based on Elliptic Curve Cryptography, but its potential vulnerabilities require further investigation.
```

Attachments:

```python
#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def gen_param(nbit):
	while True:
		t = prod([getPrime(nbit >> 3) for _ in range(4)])
		p = 4 * t ** 2 + 1
		if is_prime(p):
			c = randint(3, p - 3) ** 2 % p
			E = EllipticCurve(GF(p), [c, 0])
			if E.order() == p - 1:
				return p, c

def encrypt(m, x, p, c):
	E = EllipticCurve(GF(p), [c, 0])
	while True:
		try:
			P = E.lift_x(x)
			break
		except:
			x += 1
	assert m < p - 1
	Q = m * P
	return P, Q, m

nbit, x = 256, 1337
m = bytes_to_long(flag.lstrip(b'CCTF{').rstrip(b'}'))
p, c = gen_param(nbit)
P, Q, m = encrypt(m, x, p, c)

print(f'P = {P.x(), P.y()}')
print(f'Q = {Q.x(), Q.y()}')
```

`output.txt`:


```python
x1, y1 = (1338, 9218578132576071095213927906233283616907115389852794510465118810355739314264)
x2, y2 = (3454561753909947353764378180794889923919743476068813953002808647958908878895, 17267599534808803050751150297274989016063324917454246976792837120400888025519)
```

## Solution

We are given two points on an elliptic curve with unkown parameters. First we can find an integer that contains the prime modulus as a factor

$y_p^2 = x_p^3 + c * x_p \pmod{p}$

$y_q^2 = x_q^3 + c * x_q \pmod{p}$

We need to eliminate the part that includes `c` so:

$x_q * y_p^2 - x_p * y_q^2 = x_q * x_p^3 - x_p * x_q^3 \pmod{p}$

hence

$p\ |\ (x_q * y_p^2 - x_p * y_q^2) - (x_q * x_p^3 - x_p * x_q^3)$


```python
U = x2 * (y1**2 - x1**3) - x1 * (y2**2 - x2**3)
print(is_prime(U))
U
```

    False





    55454940004513276799611588380059302189664933020838413515384708243928267219228512844352832003082349090934777517286737687281070260517892560156083453894086877367076953177914949876201881341274104406095268673060476748059522884381040212



Yeah, unfortunately it's not prime. Yafu\factordb helped to find several small factors that we can exclude:


```python
U //= 2**2
U //= 13
U //= 577698866276004745805959
```

When I solved this, I used the fact that if we multiply a point of an elliptic curve over some ring with an curve order over some subfield then we'll catch a division by zero error(check Lenstra's ecc factorization).

So I did exactly this. I initialized an elliptic curve over $U$ and multiplied $G_1$ with all the primes $\in (2^31, 2^32)$. This primes were chosen because the order of the needed elliptic curve is $4 * (p_1 * p_2 * p_3 * p_4)^2$ where $p_i \in (2^31, 2^32)$.

With elliptic curve multiplications it took me

```python
c1 = (y1**2 - x1**3) * pow(x1, -1, U) % U
c2 = (y2**2 - x2**3) * pow(x2, -1, U) % U
assert c1 == c2

e = EllipticCurve(Zmod(U), [c1, 0])

G1 = e(x1, y1)

G = G1 * 4

pr = []
beg = 2**31
for _ in tqdm(range(100_000_000)):
    pr.append(next_prime(beg))
    beg = pr[-1]
    if pr[-1] > 2**32:
        break

kr = []
for k in tqdm(range(0, len(pr), 8)):
    kr.append(prod(pr[k:k+8]))

for p_ in tqdm(kr):
    G *= p_
```

And it took me... 


```
  9  83%|██████████████████████████████████████████████████▎           | 10242396/12272833 [2:15:32<26:52, 1259.40it/s]
 10 Traceback (most recent call last):
 11   File "/usr/lib/python3.12/site-packages/sage/schemes/elliptic_curves/ell_point.py", line 3848, in _acted_upon_
 12     pariQ = pari.ellmul(E, self, k)
 13             ^^^^^^^^^^^^^^^^^^^^^^^
 14   File "cypari2/auto_instance.pxi", line 9431, in cypari2.pari_instance.Pari_auto.ellmul
 15   File "cypari2/handle_error.pyx", line 211, in cypari2.handle_error._pari_err_handle
 16 cypari2.handle_error.PariError: impossible inverse in Fp_inv: Mod(30126567747372029007183424263223733382328264316268541293679065617875255137317, 1846015660040154116831    10167793573170730358331966325652094619483244305984538326596760638244317643986713535120290458840703944328368008698135042933291463663532512101608180908591060002406846141    3790906246868559)
```

However after the CTF was ended I rememebered that this is exactly Pollard p-1 factorization here. And it's obviously faster. By a lot.


```python
pr = []
beg = 2**31
for _ in tqdm(range(100_000_000)):
    pr.append(next_prime(beg))
    beg = pr[-1]
    if pr[-1] > 2**32:
        break

kr = []
for k in tqdm(range(0, len(pr), 8)):
    kr.append(prod(pr[k:k+8]))

g = 2**4
for p_ in tqdm(kr):
    g = pow(g, p_**2, U)
    if gcd(g - 1, U) != 1:
        print(gcd(g-1, U))
```

```
 98%|████████████████████████████████████████████████████████████▋ | 12019927/12272833 [13:10<00:16, 15210.37it/s]
```

Saved some time, huh?


```python
p = 30126567747372029007183424263223733382328264316268541293679065617875255137317
factor(p - 1)
```




    2^2 * 2281190309^2 * 2629661191^2 * 3416861837^2 * 4234051141^2




```python
c = (y1**2 - x1**3) * pow(x1, -1, p) % p # recover c

e = EllipticCurve(GF(p), [c, 0])

G1 = e((x1, y1))
G2 = e((x2, y2))

discrete_log(G2, G1, operation="+") # DLP is easy here. Check out Pohlig-Hellman
```




    68306031653152687384080876677059655513




```python
(68306031653152687384080876677059655513).to_bytes(16, 'big')
```




    b'3cC_d1ViSibil!7Y'


