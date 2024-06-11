with open("_pash_updated", "rb") as f:
    s = f.read()

i = s.index(b'\n')

Cs = eval(s[:i].decode())

blocks_ = s[i+1:]
assert len(blocks_) % 8 == 0
blocks = [int.from_bytes(blocks_[i:i+8], 'big') for i in range(0, len(blocks_), 8)]

print(f"p = {2**64 - 59}")
print(f"{Cs = }")
print(f"{blocks = }")
print(len(blocks))

for i, b in enumerate(blocks):
    print(f'hs[{i}] = conv<ZZ>("{b}");')    
print()
for i, b in enumerate(Cs):
    print(f'cs[{i}] = conv<ZZ>("{b}");')    

print(2**24 + 17)
print(2**24 + 3)

#with open("flag_txt", "rb") as f:
#    s = f.read()
#
#fblocks = [int.from_bytes(s[i:i+8], 'big') for i in range(0, len(s), 8)]
#print(fblocks)
