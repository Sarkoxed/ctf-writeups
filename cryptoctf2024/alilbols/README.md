# Crypto CTF 2024
##  Alilbols | Medium | 80 pts

Task description:

```
Alilbols, a modified version of the Alibos cryptographic algorithm, offers enhanced security features to protect sensitive and confidential data.
```

Attachments:

```python
#!/usr/bin/env python3

from Crypto.Util.number import *
from gmpy2 import *


def genkey(d):
    while True:
        f = getRandomRange(1, int(sqrt(2) * 10**d))
        g = getRandomRange(10**d, int(sqrt(2) * 10**d))
        if gcd(f, 10 * g) == 1:
            q = 4 * 100**d
            h = inverse(f, q) * g % q
            if gcd(h, 10 * d) == 1:
                break
    pkey, skey = (d, h), (f, g)
    return pkey, skey


def encrypt(m, pkey):
    d, h = pkey
    q = 4 * 100**d
    assert m < 10**d
    r = getRandomRange(1, 10**d // 2)
    c = (r * h + m + r) % q
    return c


flag = b"CCTF{aboba_aboba_aboba}"
d = 563
pkey, privkey = genkey(d)
m = bytes_to_long(flag)
c = encrypt(m, pkey)

print(f"h = {pkey[1]}")
print(f"c = {c}")
print(f"{privkey=}")
````

output.txt:


```python
h = 1051643987107349427988807326909852110640860009433515828832892541964729933410444984350917250524103015414239941369074041041830326426044333499878031164851095096864048639115431370526747014210332286314344073411522846701723463410585601251886732229726828022089809603850477551571014006202841406236367999378786782206165205893353928598469661871284779486855440579818275314024966224282757807716013799903830828885606714972634243850947534165272668985513949964901606268939300116019465522042467054120201087606016018354238401711720121586874288767235317479748890350702705575809130664969776549574720593740409234863974057904204809404816059921579771581800937241591669455683460570640868196509926763901079838233646036933530095891316054589051458146768287967886035091641162494322987627448810201550901588438560433001422233269632915351406169253963308421081459981594969405377353502889363324282815864766827664453823780238352371809048289845094882346227809082005375092441877966603138648719670349093616548820955566204871333952902983753935678447080673827214244142614295192263451840766771122229866931492260663320087497820892824540996643905125018452302747847009
c = 11913143174789215053772744981113562063689725867199301496294410323568897757042952642806438602327917861884988292757318755590132189620231444302311290566584065812614959093870787195145654508262419270742989923415342357807325941686508030706603920412262004324188375072184983301522882728578077572816154054220606088703932092256905881975876112779175003897105313776239681492514925430817300633974666123599685062340158348009344351002327049272743679109535286730751345284084148118733529966364414749672437370878526710641430471595906340522772252875146681541656231708112317601000655090279925720590940060372738708208419449824043905057860829031242339842131799965043031307394209699264362321397162645220002253271689678364848888381499587038475895945238726252440250183268252483198408039250213490525880829604473555612305513974817850974135874728084839426045420913060975464553734293001460752648937744531874552694145500413222582269910431269597066268600572899619407093373565994271589940926018891922169454906132284552523035481664164354874071831210264979733079749696197917769435226866441989054017071332158916586376454753209296136133271926449919437888563234409
```

This cryptosystem seems familiar, huh?

Go check the most basic LLL example in [Introduction to Mathematical Cryptography](https://github.com/isislovecruft/library--/blob/master/cryptography%20%26%20mathematics/An%20Introduction%20to%20Mathematical%20Cryptography%20(2014)%20-%20Hoffstein%2C%20Pipher%2C%20Silverman.pdf) somewhere at 7.1

So here we have a slightly  changed one. Well the only change is that now $c = (r * h + m + r) \pmod{q}$ instad of just $c= (r * h + m) \pmod{q}$.

Drill is kind of the same: 

setup is the following:

- choose $f \in (1, \sqrt{2} \times 10^d)$, $g \in (10^d, \sqrt{2} \times 10^d)$, $q = 4 \times 10^{2 d}$
- gcd($f, 10 * g$) here to check that f is invertible.(the only factors in q are 2 and 5 so here comes 10)
- compute $h = \frac{g}{f} \pmod{q}$
- gcd($h, 10*d$) here is to check that $g$ has no common factors with $q$. I don't know why $d$ is here. I used it to find this $d$ later. It's private here

And we're done. `pkey` = $d, h$, well, d is not quite public but whatever
`skey` = $f, g$

Encryption is simple: $c = r * h + m + r \pmod{q}$ where $r \in (1, \frac{1}{2} * 10^d$ some random nonce

As for decryption:

like in a basic variant we compute

$a = c * f = (r * \frac{g}{f} + m + r) * f = r * g  + m * f + r * f \pmod{q} = r * g  + m * f + r * f$ over the integers

Why? 

- $r * g \le \frac{1}{2} * 10^d * \sqrt{2} * 10^d = \frac{\sqrt{2}}{2} * 10^{2 * d}$
- $m * f \le 10^d * \sqrt{2} * 10^d = \sqrt{2} * 10^{2 * d}$
- $r * f \le \frac{\sqrt{2}}{2} * 10^{2 * d}$

Summing everything up: $2\sqrt{2} 10^{2 * d} \lt 4 * 10^{2 * d} = q$

Then $b = a * f^{-1} \pmod{g} = m + r \pmod{g}$

$c = a * g^{-1} \pmod{f} = r \pmod{f}$ 

We can't go to integers here, but their magnitudes are not as far, so we can check several multiples of $f$

After that we can fully recover $m$.


```python
# let's find the lower bound on d
def find():
    t1 = max(h, c)
    d = 1
    while 4 * 10 ** (2 * d) < t1 or gcd(h, 10 * d) != 1:
        d += 1
    return d
find()
```




    563



The problem is exactly with the strict bounds on the parameters:

We can construct a Lattice:

\begin{align*}
L &= \begin{pmatrix}
1 & h \\
0 & -q \\
\end{pmatrix}
\end{align*}


And there's vector $\vec{v} = (f, R)$: $\vec{v} * L = (f, f * g - R * q) = (f, h)$ that is kind of small and inside $L$. <b>LLL<b>.


```python
from tqdm import tqdm
```


```python
d0 = 563
for d in tqdm(range(d0, d0 + 500)):
    try:
        assert gcd(h, 10 * d) == 1

        q = 4 * 10 ** (2 * d)
        M = Matrix([[1, 0], [h, -q]]).T
        T = M.LLL()

        f1, g1 = T[0]
        assert f1 * g1 > 0
        
        f1 = abs(f1)
        g1 = abs(g1)

        assert gcd(f1, 10 * g1) == 1
        assert g1 < int(sqrt(2) * 10**d)
        assert g1 > 10**d
        assert f1 < int(sqrt(2) * 10**d)
        assert (g1 * pow(f1, -1, q) % q) == h

        a = ((c * f1) % q) * pow(f1, -1, g1) % g1
        r1 = ((c * f1) % q) * pow(g1, -1, f1) % f1  # r mod (f1)

        tmp = (10**d // 2 - r1) // f1
        assert tmp >= 0

        while r1 < 10**d // 2 and a - r1 > 0:
            print((a - r1).to_bytes(64, "big"))
            r1 += f1
    except:
        continue
```

      4%|█▌                                    | 21/500 [00:00<00:03, 151.04it/s]

    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00CCTF{4_c0N9rU3n7!aL_Pu81iC_k3Y_cRyp70_5ySTeM_1N_CCTF!!}'


    100%|████████████████████████████████████| 500/500 [00:00<00:00, 1039.20it/s]

