# Crypto CTF 2024
##  RM2 | Medium | 75 pts

Task description:

```
The RM2 cryptosystem is a minimalist design that exhibits remarkable resilience, making it exceptionally difficult to compromise.

nc 01.cr.yp.toc.tf 13371
```

Attachments:

```python
#!/usr/bin/env python3

import sys
from Crypto.Util.number import *
from string import *
from random import *
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

def encrypt(msg, p, q):
	e = 65537
	m1, m2 = msg[:len(msg) >> 1], msg[len(msg) >> 1:]
	m1, m2 = bytes_to_long(m1), bytes_to_long(m2)
	c1, c2 = pow(m1, e, (p - 1) * (q - 1)), pow(m2, e, (2*p + 1) * (2*q + 1))
	return (c1, c2)

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".: Welcome to RM2 task! Your mission is break our cryptosystem :. ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit, _b = 1024, False
	pr(border, f"Please provide your desired {nbit}-bit prime numbers p, q:")
	inp = sc().decode()
	try:
		p, q = [int(_) for _ in inp.split(',')]
		if p.bit_length() == q.bit_length() == nbit and isPrime(p) and isPrime(q) and p != q:
			_b = True
	except:
		die(border, f"The input you provided is is not valid!")
	if _b:
		e, n =  65537, p * q
		s = randstr(nbit >> 4).encode()
		m = bytes_to_long(s)
		assert m < n >> 2
		c1, c2 = encrypt(s, p, q)
		pr(border, f'c1 = {c1}')
		pr(border, f'c2 = {c2}')
		pr(border, f'Now, send us the secret string to get the flag: ')
		_m = sc().strip()
		if _m == s:
			die(border, f'Congrats, you got the flag: {flag}')
		else:
			die(border, f'The secret string is not correct! Bye!!')
	else:
		die(border, f"Your input does not meet the requirements!!!")

if __name__ == '__main__':
	main()
```

## Solution

Well, this one is pretty straighforward. We need to send such primes, that we know factorizations of `p - 1` and `2p + 1`. Then we can simply calculate the totient function and get the private exponent. 

There's nothing clever here, I just took smooth prime numbers(such that `p - 1` is a product of small primes and hoped that `2p+1` will be factorizable. 

And it happend twice. Took me 20 mintues I guess.

You can find the smooth number creation [here](create_smooth_primes.py) and factor logs [here](factor.json)


```python
from Crypto.Util.number import getPrime, isPrime
from sage.all import prod

p = 170801077092492573570517165775571413020233676815110846780878960995242044774306196509406867772218349594256991186221524252252034531354007762422579141391522827293823345712605467604574196054406553151149952205702771434645023424007219353919908173942460143313464197512599463263363481967283220682398987271795532844839
p1 = [int(x) for x in ["2","9473","60527","51001","48533","33937","58391","36563","36563","51713","10837","36571","44917","55603","32917","32917","61409","54833","49463","52163","37813","33581","62189","54907","49783","47459","36187","60427","55667","36307","36299","37397","34301","53717","52249","34877","60869","63277","55127","52769","44729","62987","64091","55661","58549","57389","56923","52147","50131","54361","34613","51949","61627","56597","52489","53731","41659","52883","60631","52919","62297","42901","52253","48079","41453","63281","33893"]]
p2 = [163, 21929, 27754595086177, 3443334968360926541015084155971133299714495127884970323545733732988982215020175940426581412825373049245001549018432084217463812957329615044141979466138383056916564401987041931237195474228725253739636032562152538479975208865330318310636230572890913721443916781262765066384161876844322187901] 

assert isPrime(p)
assert prod(p1) == p - 1
assert prod(p2) == 2 * p  +1
assert p.bit_length() == 1024


q = 110167340227476484562958206301061045302168984062025687888662354602576815388130980953204083817071660335436643258121282142356984569337962966652991576402035381786414013180243882336471954512219312126981465823016249822177501762005739240896831845679073432261837987003910833081466975371615145936514966108026966555343
q1 = [2, 8387, 10567, 32779, 33703, 35111, 35617, 35899, 37171, 37589, 37783, 38237, 38299, 38393, 38959, 39119, 39181, 39749, 41039, 41257, 41491, 42073, 42193, 42337, 43151, 43793, 44101, 44119, 44507, 45197, 46181, 46273, 47269, 47497, 47681, 49531, 50051, 50587, 51283, 51287, 51517, 52747, 53087, 53401, 53597, 54469, 55313, 55697, 55763, 56701, 56767, 56783, 56989, 57793, 59581, 60617, 61981, 62791, 63533, 63589, 63671, 63691, 63839, 64783, 64793, 64817, 64901]
q2 = [67, 2106394188443, 1561235469726595794510192733675595089645365924831500465163794211675776015762883947944082812245540374346110322896671983652344313487932610633555776607915152588737217683433099453787078092068675729644667806051432890700663466962673637498793187760534724038374337973153155404942878076945424339519873327]

assert isPrime(q)
assert prod(q1) == q - 1
assert prod(q2) == 2 * q  +1
assert q.bit_length() == 1024

f1 = q1 + p1
f2 = q2 + p2
assert len(f2) == len(set(f2))
f1 = sorted([(x, f1.count(x)) for x in set(f1)], key=lambda x: x[0])
```


```python
from pwn import remote
import re

host, port = "01.cr.yp.toc.tf", 13371
r = remote(host, port)
print(r.recvline().decode("utf-8"))
print(r.recvline().decode("utf-8"))
print(r.recvline().decode("utf-8"))
print(r.recvline().decode("utf-8"))

r.sendline(f"{p},{q}".encode())
```

    [x] Opening connection to 01.cr.yp.toc.tf on port 13371
    [x] Opening connection to 01.cr.yp.toc.tf on port 13371: Trying 65.109.218.140
    [+] Opening connection to 01.cr.yp.toc.tf on port 13371: Done
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    
    ┃ .: Welcome to RM2 task! Your mission is break our cryptosystem :.  ┃
    
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    
    ┃ Please provide your desired 1024-bit prime numbers p, q:
    


And here's the extended RSA version decryption happening


```python
from sage.all import crt

c1 = int(re.findall(r'c1 = (.*)\n', r.recvline().decode())[0])
c2 = int(re.findall(r'c2 = (.*)\n', r.recvline().decode())[0])

e = 0x10001

mods = []
rems = []
for p1, e1 in f1:
    mods.append(p1**e1)
    d1 = pow(e, -1, p1**(e1 - 1) * (p1 - 1))
    m1 = pow(c1, d1, p1**e1)

    assert pow(m1, e, p1**e1) == c1 % p1**e1
    rems.append(m1)

m = int(crt(rems, mods))
assert pow(m, e, (p - 1) * (q - 1)) == c1
m_1 = m.to_bytes(32, 'big').decode()
print(m_1)


rems = []
for p1 in f2:
    d1 = pow(e, -1, p1 - 1)
    m1 = pow(c2, d1, p1)

    assert pow(m1, e, p1) == c2 % p1
    rems.append(m1)

m = int(crt(rems, f2))
assert pow(m, e, (2 * p + 1) * (2 * q + 1)) == c2
m_2 = m.to_bytes(32, 'big').decode()
print(m_2)

ans = m_1 + m_2
print(ans)
r.sendline(ans.encode())
print(r.recvline().decode("utf-8"))
print(r.recvline().decode("utf-8"))
```

    DfF"P1.,s:WDUiNUi0)<(MSP0IP'(!>e
    I\]EWer2/){ir!w%rPf34f6(>e]/&MR[
    DfF"P1.,s:WDUiNUi0)<(MSP0IP'(!>eI\]EWer2/){ir!w%rPf34f6(>e]/&MR[
    ┃ Now, send us the secret string to get the flag: 
    
    ┃ Congrats, you got the flag: b'CCTF{i_l0v3_5UpeR_S4fE_Pr1m3s!!}'
    

