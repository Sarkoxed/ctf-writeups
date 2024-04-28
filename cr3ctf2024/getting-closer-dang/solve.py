from itertools import product, combinations
from Crypto.Util.number import isPrime
from Crypto.Cipher import AES
from math import gcd, prod
from hashlib import sha256
from Crypto.Util.Padding import unpad
from tqdm import tqdm
import sys

sys.set_int_max_str_digits(100000)

N = 13185232652915309492470700885494158416479364343127310426787872363041960044885500175769971795951432028221543122753022991035176378747918784016983155565886369
out = {
    "iv": "6f69ac380715dbf9b00ef32ca8c204bb",
    "ct": "e654237a76d61d3bf97b315af1c2a517797b34b8eca270dbc8132dda1f425065b7b84690d4c21cdaf2ab17c2876738ed",
}


def prime_range(n):
    pr = []
    for a in range(2 ** (n - 1), 2**n):
        if isPrime(a):
            pr.append(a)
    return pr


pr = prime_range(9)

res_range = (
    list(combinations(pr, r=1))
    + list(combinations(pr, r=2))
    + list(combinations(pr, r=3))
)
print(res_range)

for t in tqdm(res_range):
    power = prod(t)
    g = pow(N, power) - 1
    key = sha256(str(g).encode()).digest()[:16]
    iv = bytes.fromhex(out["iv"])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.decrypt(bytes.fromhex(out["ct"]))
    try:
        pt = unpad(ct, 16)
        print(pt)
        break
    except:
        continue
