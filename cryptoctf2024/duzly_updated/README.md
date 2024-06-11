# Crypto CTF 2024
##  Duzly | Medium | 500 pts(no solves)

Task description:

```
Duzly is a straightforward hash function design based on congruence relationships over a prime number modulus.

Note: Please redownload the attachment!
```

Attachments:

```python
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
```
---

[output](./_pash_updated)


```python
p = 2**64 - 59
```


```python
with open("_pash_updated", "rb") as f:
    s = f.read()

i = s.index(b'\n')

Cs = eval(s[:i].decode())
Es = [2**24 + 17, 2**24 + 3, 3, 2, 1, 0]

blocks_ = s[i+1:]
assert len(blocks_) % 8 == 0
blocks = [int.from_bytes(blocks_[i:i+8], 'big') for i in range(0, len(blocks_), 8)]
```

## Solution

Here's an easy task. We have a polynomial. And we have it's evaluation. Find the root. Well...

The polynomial is of the degree $2^{24} + 17$. It's tough. Let's simplify this task a little. 


First we need to somehow reduce this humongous power.

First let's denote the poly as $H(x) = x^{2^{24} + 17} + c_1 * x^{2^{24} + 3} + c_2 * x^3 + c_3 * x^2 + c_2 * x + c_3$

We know that $H(b_i) = h_i$

Let's extract the `real` part of this polynomial. We need to find the   $\gcd(x^{p-1} - 1, H(x) - h_i)$

Why?  Because $x^{p-1} - 1$ or so called Field Polynomial. It has all the integers $(1, p-1)$ as it's roots. Thanks to Fermat. 

So if we take the gcd, we will remove all the irreducible parts from $H(x) - h_i$. 

But $x^{p-1}$ is huge. $\approx x^{2^{64}}$. So we need to be smart. 

First optimization is to raise $x$ to the power $p-1$ modulo $H(x) - h_i$. That will keep the powers somewhat reasonable. 

After computing $x^{p-1} \pmod{H(x) - h_i}$ we can take the ordinary gcd and recover the kind of small polynomial. Well, it should be small.  

If we try to do that in sage with something like this:

```python
def fastpow(x, n, c):
    res = x
    for h, i in enumerate(bin(n)[3:]):
        print(f"{h}/{n.bit_length() - 1}")
        res = pow(res, 2, c)
        if i == "1":
            res = (res * x) % c
    return res
```

We will bump into the following error after raising $x$ to the $2^{24}$ power: 

`Polynomial too big for FFT`

Also the initialization time for the `c` poly was big. So I decided to move to `c++`. I tried using `NTL` library to work with polynomials but obviously the error was still present. Because sage uses `NTL` too. 

Then after reading a little of `NTL` source code I found these two lines:


`src/ZZ_pX.cpp`:

```c++
   if (k > FFTInfo->MaxRoot)
      ResourceError("Polynomial too big for FFT");
```

`include/NTL/FFT.h`

```c++
#define NTL_FFTMaxRootBnd (NTL_SP_NBITS-2)
// Absolute maximum root bound for FFT primes.
// Don't change this!

#if (25 <= NTL_FFTMaxRootBnd)
#define NTL_FFTMaxRoot (25)
#else
#define NTL_FFTMaxRoot  NTL_FFTMaxRootBnd
#endif
// Root bound for FFT primes.  Held to a maximum
// of 25 to avoid large tables and excess precomputation,
// and to keep the number of FFT primes needed small.
// This means we can multiply polynomials of degree less than 2^24.
// This can be increased, with a slight performance penalty.
```

So I changed it to `26` and [recompiled](https://libntl.org/doc/tour-gmp.html) the library. 

---

### C++ script

### Standard includes

```c++
#include <NTL/ZZ_pXFactoring.h>
#include <chrono>
#include <vector>

using namespace NTL;
```

### `p-1` binary decomposition(starting from the second bit)

```c++
std::vector<uint32_t> p_1_bin = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                                 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0};
```

### fast pow mod poly

```c++
ZZ_pX fast_pow_p_1(ZZ_pX &x, const ZZ_pX &mod) {
  ZZ_pX res = x;
  int j = 0;
  for (auto i : p_1_bin) {
    // std::cout << "Round: " << j << "/63" << std::endl;
    res = (res * res) % mod;
    if (i == 1) {
      res = (res * x) % mod;
    }
    j += 1;
  }
  return res;
}
```

### find_roots function.

```c++
void find_roots(ZZ_p h, const ZZ_pX &c, uint32_t argnum) {
  ZZ_pX mod;
  auto start = std::chrono::high_resolution_clock::now();

  SetCoeff(mod, 0, -h);                                        // Calculating H(x) - h_i
  mod += c;

  auto stop = std::chrono::high_resolution_clock::now();
  uint32_t duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "Init 2 Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  ZZ_pX x;
  SetCoeff(x, 1, 1);

  start = std::chrono::high_resolution_clock::now();

  ZZ_pX x_p_1 = fast_pow_p_1(x, mod);                          // Calculating x^{p-1} mod(H(x) - h_i)

  stop = std::chrono::high_resolution_clock::now();
  duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "Pow p-1 Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  ZZ_pX gcd;
  start = std::chrono::high_resolution_clock::now();

  GCD(gcd, x_p_1 - 1, mod);                                  // Calculating gcd(x^{p-1}-1, H(x) - h_i)

  stop = std::chrono::high_resolution_clock::now();
  duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "GCD Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  Vec<Pair<ZZ_pX, long>> factors;
  start = std::chrono::high_resolution_clock::now();

  CanZass(factors, gcd); // calls "Cantor/Zassenhaus" algorithm  for roots
                         //
  stop = std::chrono::high_resolution_clock::now();
  duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << argnum << " - "
            << "Factor Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;
  //
  std::cout << argnum << "factors = " << factors << std::endl;
}
```


### And the main function:


```c++
int main(int argc, char **argv) {
  ZZ p = conv<ZZ>("18446744073709551557");
  ZZ_p::init(p);

  std::vector<ZZ_p> cs;
  cs.push_back(conv<ZZ_p>("1"));
  cs.push_back(conv<ZZ_p>("17761542461647558231"));
  cs.push_back(conv<ZZ_p>("13293668011354679701"));
  cs.push_back(conv<ZZ_p>("9204760597720472707"));
  cs.push_back(conv<ZZ_p>("8540722934676348527"));
  cs.push_back(conv<ZZ_p>("3568330912555059249"));

  std::vector<ZZ_p> hs(24);
  hs[0] = conv<ZZ_p>("2988030636007782305");
  hs[1] = conv<ZZ_p>("12072493504983501068");
  hs[2] = conv<ZZ_p>("6455555549858422687");
  hs[3] = conv<ZZ_p>("332674325673811430");
  hs[4] = conv<ZZ_p>("1365214988046232242");
  hs[5] = conv<ZZ_p>("8747631820355484079");
  hs[6] = conv<ZZ_p>("18123548747649932808");
  hs[7] = conv<ZZ_p>("13046626162506912628");
  hs[8] = conv<ZZ_p>("2218632231558076393");
  hs[9] = conv<ZZ_p>("3370337767665008202");
  hs[10] = conv<ZZ_p>("10801882347401505353");
  hs[11] = conv<ZZ_p>("12241743889746753324");
  hs[12] = conv<ZZ_p>("1408885656997934913");
  hs[13] = conv<ZZ_p>("580550489477911343");
  hs[14] = conv<ZZ_p>("18325674811173222161");
  hs[15] = conv<ZZ_p>("5163042577640987924");
  hs[16] = conv<ZZ_p>("4374658315402249035");
  hs[17] = conv<ZZ_p>("3049637019635323521");
  hs[18] = conv<ZZ_p>("4633465126861589844");
  hs[19] = conv<ZZ_p>("12895858433491142556");
  hs[20] = conv<ZZ_p>("2580453314653954697");
  hs[21] = conv<ZZ_p>("7139242178290800255");
  hs[22] = conv<ZZ_p>("12516366163786112763");
  hs[23] = conv<ZZ_p>("18065580967927811201");

  uint32_t argnum = std::stoi(argv[1]);

  ZZ_pX mod;

  auto start = std::chrono::high_resolution_clock::now();

  SetCoeff(mod, 0, cs[5]);
  SetCoeff(mod, 1, cs[4]);
  SetCoeff(mod, 2, cs[3]);
  SetCoeff(mod, 3, cs[2]);
  SetCoeff(mod, 16777219, cs[1]);
  SetCoeff(mod, 16777233, cs[0]);

  auto stop = std::chrono::high_resolution_clock::now();
  uint32_t duration_secs = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(stop - start).count());
  std::cout << "Init Time elapsed: " << duration_secs / 60 << " min "
            << duration_secs % 60 << " sec" << std::endl;

  find_roots(hs[argnum], mod, argnum);

  return 0;
}
```

## Compilation

`clang++ solve.cpp -o solve.out -Ofast -I$HOME/tmp_lib/include -L$HOME/tmp_lib/lib -lntl -lgmp`

## Final steps

For each value it took me around a hour to compute the root. And also my memory went off the limit. And my laptop crashed. It was frustrating. 
So I had to rent the machine in a compute cloud.

The first attemt to launch 24 processes failed. So I decided to binary search.
First one was 12:

```% ./solve.out 12
Init Time elapsed: 0 min 0 sec
12 - Init 2 Time elapsed: 0 min 0 sec
12 - Pow p-1 Time elapsed: 32 min 4 sec
12 - GCD Time elapsed: 8 min 44 sec
12 - Factor Time elapsed: 0 min 0 sec
12factors = [[[14120995930127651906 1] 1] [[4084536194506866104 1] 1] [[10572323037051791211 1] 1] [[13599933788034343005 1] 1]]
```



```python
def hash_(m):
    return sum(Cs[i] * pow(m, Es[i], p) for i in range(len(Cs))) % p

factors = [-14120995930127651906, -4084536194506866104, -10572323037051791211, -13599933788034343005]
for fac in factors:
    print(hash_(fac))
```

    1408885656997934913
    1408885656997934913
    1408885656997934913
    1408885656997934913



```python
blocks[12]
```




    1408885656997934913




```python
for fac in factors:
    print((p + fac).to_bytes(8, 'big'))
```

    b'<\x08%\x04\x8e\x01+\x83'
    b'\xc7P\xcf\xf8\xce1B\r'
    b'mG\x906]\xd9XZ'
    b'CCTF{a_h'


Well... That was hell of a luck, huh?. Ok now we know where to go next

```
% ./solve.out 13 &
./solve.out 14 &

13 - Init 2 Time elapsed: 0 min 0 sec
14 - Init 2 Time elapsed: 0 min 0 sec
13 - Pow p-1 Time elapsed: 32 min 39 sec
14 - Pow p-1 Time elapsed: 33 min 8 sec
13 - GCD Time elapsed: 8 min 47 sec
13 - Factor Time elapsed: 0 min 0 sec
13 - factors = [[[12137707653155235772 1] 1] [[16052719823032589424 1] 1]]
14 - GCD Time elapsed: 8 min 47 sec
14 - Factor Time elapsed: 0 min 0 sec
14 - factors = [[[10218325222534401918 1] 1]]
```


```python
for fac in [12137707653155235772, 16052719823032589424]:
    print((p - fac).to_bytes(8, 'big'))
```

    b'W\x8e32\xa2$X\t'
    b'!9H_5EcU'



```python
print((p - 10218325222534401918).to_bytes(8, 'big'))
```

    b'r17Y_l0G'


```% ./solve.out 15 &
./solve.out 16 &
./solve.out 17 &

15 - Init 2 Time elapsed: 0 min 0 sec
16 - Init 2 Time elapsed: 0 min 0 sec
17 - Init 2 Time elapsed: 0 min 0 sec
15 - Pow p-1 Time elapsed: 33 min 21 sec
17 - Pow p-1 Time elapsed: 33 min 27 sec
16 - Pow p-1 Time elapsed: 34 min 2 sec
15 - GCD Time elapsed: 8 min 51 sec
15 - Factor Time elapsed: 0 min 0 sec
15 - factors = [[[4863702914920033027 1] 1] [[17868627184818030268 1] 1] [[15194777496492814434 1] 1]]
17 - GCD Time elapsed: 8 min 51 sec
17 - Factor Time elapsed: 0 min 0 sec
17 - factors = [[[4663377151319611377 1] 1] [[12655666371965753797 1] 1] [[16124524800165402045 1] 1]]
16 - GCD Time elapsed: 8 min 53 sec
16 - Factor Time elapsed: 0 min 0 sec
16 - factors = [[[2385757573244289630 1] 1] [[14743565331131719240 1] 1] [[3507998132376886209 1] 1]]
```



```python
for fac in [4863702914920033027, 17868627184818030268, 15194777496492814434]:
    print((p - fac).to_bytes(8, 'big'))

for fac in [4663377151319611377, 12655666371965753797, 16124524800165402045]:
    print((p - fac).to_bytes(8, 'big'))

for fac in [2385757573244289630, 14743565331131719240, 3507998132376886209]:
    print((p - fac).to_bytes(8, 'big'))
```

    b'\xbc\x80\xa7\xf7\xc7(\xd4\xc2'
    b'\x08\x05\xe2?Y\x08y\t'
    b'-!N_PrOc'
    b'\xbfH[0A\xeb\xe7\xd4'
    b'P^\n|\xbf\x1f\xe6\x00'
    b' :. ***\x08'
    b'\xde\xe4\x16 \x9e\x93}g'
    b'3dUr3!!}'
    b'\xcfQ\x16H\xe6\xf1$\x04'



```python
flag = b'CCTF{a_h' + b'!9H_5EcU' + b'r17Y_l0G' + b'-!N_PrOc' + b'3dUr3!!}'
```


```python
flag
```




    b'CCTF{a_h!9H_5EcUr17Y_l0G-!N_PrOc3dUr3!!}'



Yeah it took me 2hrs only to run the scripts. I don't know if there's any elaborate solution. But noone solved this task, so....
