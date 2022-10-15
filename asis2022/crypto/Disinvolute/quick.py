from pwn import remote
host, port = "65.21.255.31", 12431
#host, port = "188.34.203.80", 12431
from factordb.factordb import FactorDB

import re
def get_num(x):
    return re.findall(r'[\d]+', x)[0]

r = remote(host, port)
r.sendline(b"F")
r.sendline(b"E")
r.sendline(b"Q")

for i in range(10):
    r.recvline()
tmp = [r.recvline().decode() for _ in range(5)]
g, G, n, x, y = [get_num(x) for x in tmp]
print(g, G)

for i in range(6):
    r.recvline()

tmp = r.recvline().decode()
c = get_num(tmp)

r.close()
q = FactorDB(abs(int(x)-int(y)))
q.connect()

try:
    assert abs(int(x)-int(y)) % int(G) == 0
    print("asserted")
except Exception as e:
    print("not asserted")
    print(e)

with open("params.py", "wt") as f:
    f.write(f"g = {g}\nG = {G}\nn = {n}\nx = {x}\ny = {y}\nc = {c}\ne = {2**16 + 1}\n")
