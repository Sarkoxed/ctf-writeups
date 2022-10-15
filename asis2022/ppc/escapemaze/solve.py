from pwn import remote, process
import re
host, port = "65.21.255.31", 34979
r = remote(host, port)
#r = process("./escapemaze.py")
rooms, tries = 114, 114//2

def round(r):
    m = r.recvline().decode()
    n = re.findall(r"[\d]+", m)[0]
    print(n, end=" ", flush=True)
    for _ in range(tries):
        r.recvline()
        r.sendline(n.encode())
        m = r.recvline().decode()
        n = re.findall(r"[\d]+", m)[0]
        m = r.recvline()
        if b"Great" in m:
            if b'flag' in m:
                print(m)
                exit(0)
            return True
        elif b"Sorry" in m:
            return False

for i in range(8):
    r.recvline()

k = 0
while True:
    print(f"Rooms({k}): ", end="", flush=True)
    for i in range(rooms):
        t = round(r)
        if not t:
            break
    k += 1
    print()
