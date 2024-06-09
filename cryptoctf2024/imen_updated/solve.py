from pwn import remote
from sage.all import Matrix, prod

host, port = "03.cr.yp.toc.tf", 31117
r = remote(host, port)

for _ in range(4):
    r.recvline()

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


def get_permutation(ms, tmpm, perm):
    print(perm)
    if len(perm) == len(ms):
        if tmpm.is_one():
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


for round_ in range(12):
    ms = get_matrices(r, round_)
    M = get_M(r)
    
    perm = get_permutation(ms, Matrix(M), [])
    assert perm is not None
   
    assert prod(ms[i] for i in perm) == M
    print(submit(r, perm))
