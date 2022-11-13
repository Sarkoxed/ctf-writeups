from pwn import remote
import re
from Crypto.Util.number import long_to_bytes, getStrongPrime, bytes_to_long
from random import randint
from gmpy2 import mpq

d = 0

def floor(a, b):
    return a // b


def ceil(a, b):
    return (a + b - 1) // b


def valid_pad_2(r, c):
    r.sendline(str(c).encode())
    x = r.recvline().decode()[:-1]
    x = re.findall(r"c = (.*)", x)[0]
    if x == "True":
        return True
    elif x == "False":
        return False
    return "pizda"


# padding format: 0b0011111111........
def valid_pad_1(r, c):
    padding_pos = n.bit_length() - 2
    m = pow(c, d, n)

    return (m >> (padding_pos - 8)) == 0xFF


def params_1():
    r = 1
    flag_text = bytes_to_long(b"aboba")
    length = flag_text.bit_length()
    p = getStrongPrime(512)
    q = getStrongPrime(512)
    e = 0x10001
    n = p * q

    phi = (p - 1) * (q - 1)
    global d
    d = pow(e, -1, phi)

    print(length, n, flag_text)
    exit(0)
    # Oops! encrypt without padding!
    c = pow(flag_text, e, n)
    return r, n, length, c, 2**16 + 1


def params_2():
    r = remote("this-is-not-lsb.seccon.games", 8080)
    m = r.recvline()
    n = re.findall(r"n = (.*)\n", m.decode())[0]
    n = int(n)
    r.recvline()
    m = r.recvline()
    length = re.findall(r"flag_length = (.*)\n", m.decode())[0]
    length = int(length)
    m = r.recvline()
    c = re.findall(r"c = (.*)\n", m.decode())[0]
    c = int(c)
    return r, n, length, c, 2**16 + 1


params = params_2
valid_pad = valid_pad_2

r, n, length, c, e = params()
t1 = n.bit_length()
x0 = "00" + 8 * "1" + "0" * (t1 - 10)
x1 = "00" + 8 * "1" + "1" * (t1 - 10)
oracle_calls = 0
global_oracle = 0

print("Started attack")
k = len(long_to_bytes(n))
UB = int(x1, 2) + 1
LB = int(x0, 2)
oracle_calls = 0

while True:
    s0 = randint(1, n - 1)
    c0 = (c * pow(s0, e, n)) % n
    oracle_calls += 1
    if valid_pad(r, c0):
        con = True
        break


print(oracle_calls)
global_oracle, oracle_calls = oracle_calls, 0

c0 = (c * pow(s0, e, n)) % n
Ms = set([(LB, UB - 1)])
round = 1

s = floor(UB, n)
while True:
    print("Round = ", round, end=" ", flush=True)
    if len(Ms) >= 2:
        for si in range(s + 1, n):
            c1 = (c0 * pow(si, e, n)) % n
            oracle_calls += 1
            if valid_pad(r, c1):
                print(f"Round {round} oracle calls: ", oracle_calls)
                global_oracle, oracle_calls = global_oracle + oracle_calls, 0
                s = si
                break

    elif len(Ms) == 1:
        a, b = list(Ms)[0]
        flag = False

        ri_start = ceil(2 * (b * s - LB), n)
        for ri in range(ri_start, n):
            si_start = ceil(LB + ri * n, b)
            si_end = floor(LB - 1 + ri * n, a)

            for si in range(si_start, si_end + 1):
                c1 = (c0 * pow(si, e, n)) % n
                oracle_calls += 1
                if valid_pad(r, c1):
                    print(f"Round {round} oracle calls: ", oracle_calls)
                    global_oracle, oracle_calls = global_oracle + oracle_calls, 0
                    s = si
                    flag = True
                    break
            if flag:
                break

    tmp = set([])
    for a, b in Ms:
        r_lower = ceil(a * s - UB + 1, n)
        r_upper = floor(b * s - LB, n)
        for r1 in range(r_lower, r_upper + 1):
            a1 = ceil(LB + r1 * n, s)
            b1 = floor(UB - 1 + r1 * n, s)
            newa = max(a, a1)
            newb = min(b, b1)
            if newa <= newb:
                tmp.add((newa, newb))

    if len(tmp) > 0:
        Ms = tmp

    if round % 20 == 0:
        print(Ms)

    if len(Ms) == 1:
        a, b = list(Ms)[0]
        if a == b:
            print(f"Finished in {round} rounds. Total oracle calls: {global_oracle}.")
            print(long_to_bytes((a * pow(s0, -1, n)) % n))
            exit(0)
    round += 1
