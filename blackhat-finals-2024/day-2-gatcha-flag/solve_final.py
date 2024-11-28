from pwn import remote
import re
from base64 import urlsafe_b64encode
from challenge import Random, B64Dec, DROP_TABLE, DROPS, B64Enc
from random import randint
from tqdm import tqdm


####################### Client stuff #######################

def skip_menu(r):
    (r.recvuntil(b'uit\n'))
    r.recvline()

def login(r, login, enc=False):
    skip_menu(r)
    r.sendline(b'l')
    r.recvline()
    if enc:
        username = urlsafe_b64encode(login.encode())
    else:
        username = login.encode()
    r.sendline(username)
    r.recvline()
    r.recvline()
    r.recvline()

def choice(r):
    skip_menu(r)
    r.sendline(b's')
    r.recvline()
    res = r.recvline().decode()
    rarity = re.findall(r'got a (.*) pull', res)[0]
    res = r.recvline().decode()
    value = re.findall(r'pull = (.*)\n', res)[0]
    return rarity, value

def pull(r):
    skip_menu(r)
    r.sendline(b'p')
    r.recvline()
    r.recvline().decode()
    res = r.recvline().decode()
    return eval(re.findall(r'pulls = (.*)\n', res)[0])

def parse_pull(p):
    i = 0
    res = []
    while len(res) < 1000:
        if p[i] == ' ':
            res.append(("common", ' '))
            i += 1
        elif p[i] == 'b' and i + 1 < len(p) and p[i] != ' ':
            res.append(("rare", int(p[i+1])))
            i += 2
        elif p[i] == 'x':
            res.append(("epic", int(p[i+1], 16)))
            i += 2
        else:
            res.append(("legendary", p[i]))
            i += 1
    if len(res) != 1000:
        raise ValueError("failed")
    return res

# turns the output stream of the kind (("common", " "), ("rare", "b1"), .. ) into _Randint(0, 9) values

def parse_rarity_output(out, rarity):
    slice_len = DROP_TABLE[rarity][0]
    rarities = [x[0] for x in out]
    contents_per_layer = [rarities[i:i+slice_len] for i in range(0, len(rarities), slice_len)]

    randint_out = []
    for layer in contents_per_layer:
        init_len = len(randint_out)
        if rarity in layer:
            randint_out.append(layer.index(rarity))
        else:
            tmp = []
            for j, x in enumerate(layer):
                if DROPS.index(x) < DROPS.index(rarity):
                    continue
                else:
                    tmp.append(j)
            if len(tmp) == 1:
                randint_out.append(tmp[0])
            elif len(tmp) == 0:
                randint_out.append(f"> {len(layer)}")
            else:
                randint_out.append(tmp)
    return randint_out

def stack_pull(r, n, f=False):
    if f:
        return parse_pull(pull(r))
    return [choice(r) for _ in range(n)]

#print(get_overflow_prob(10)) # 6 / 16

# get a seed such that bitstream[skip: skip + bl] == value

def get_random_for_rare(value, bl, skip=0):
    for _ in range(2**32):
        seed = randint(0, 2**32)
        R = Random(seed)
        if skip > 0:
            R.GetRandBits(skip)
        if R.GetRandBits(bl) == value:
            return seed

# recover nth User.__srng._Randint(0, 9) output
# bitstream is alreay recovered bits

def get_next_rare(r, bitstream):
    bound = DROP_TABLE['rare'][0] # 10
    bl = (bound-1).bit_length()
    assert len(bitstream) % bl == 0

    reses = []
    max_stream_output_idx = 0

    recovered_server_rares = [int(bitstream[i:i+4], 2) for i in range(0, len(bitstream), 4)]
    skip_rare_bits = len(bitstream)
    
    # iterate over [0: 15] in 9/16 of cases it will not overflow the 9 Randint bound. 
    # so just take the most frequent value out of [(server_out_j - j) % 2**4]
    for j in range(2**bl):
        while True:
            seed = get_random_for_rare(j, bl, skip_rare_bits)
            seedb64 = B64Enc(seed)
            
            R = Random(seed)
            user_rand_out = [R.GetRandBits(bl) for _ in range(skip_rare_bits // 4 + 1)]
            assert user_rand_out[-1] == j
            
            # calculate the amount of overflows with current seed
            stream_output_idx = 0
            for srand, urand in zip(recovered_server_rares, user_rand_out):
                tmp = (srand + urand) % 2**bl
                if tmp <= (bound - 1):
                    stream_output_idx += 1
            
            # we can get only 100 outputs, excluding overflow count
            if stream_output_idx >= (1000 // bound):
                continue

            login(r, seedb64, False)
            
            use_pull_1000 = True
            out = stack_pull(r, (stream_output_idx + 1) * bound, f=use_pull_1000)

            rare = parse_rarity_output(out, 'rare')
            if all(isinstance(x, int) for x in rare):
                break
        
        if stream_output_idx > max_stream_output_idx:
            max_stream_output_idx = stream_output_idx

        reses.append((rare[stream_output_idx] - j) % 2**bl) # get the true server randbits(4) output

    s = max(reses, key=lambda x: reses.count(x))
    bitstream += bin(s)[2:].zfill(bl)
    print(f"{max_stream_output_idx}/100 used to retrieve {len(bitstream)} bits")
    return bitstream


host, port = "localhost", 1337
#host, port = "blackhat.flagyard.com", 30452
r = remote(host, port)

# Time elapsed: 193.4724349975586 - localhost
# I have no idea how long it would have taken over the network but it sucked so much I was not able to get even one pull
def get_bitstream(bitlength=800):
    from time import time

    bitstream = ''
    start = time()
    
    target_bitlen = bitlength
    for i in range(target_bitlen // 4):
        bitstream = get_next_rare(r, bitstream)
    end = time()
    print(f"Time elapsed: {end - start}")
    print(f"{bitstream = }")

print("Minimal amount of bits needed: ")
print(-(-1000 // 10) * 4 + -(-1000 // 80) * 7 + -(-1000 // 380) * 9 + 32)
#bitstream = get_bitstream()
bitstream = '10010111100001011011001010111001011011010101010011010111010011010111010101011000011010010111000001011000000100100110111111010101010101100011110101010100010100110111100010011000000000011111001101000010101110110001101001011010010101101100010111000110001101100001011111111101001101110101010111000010011010000100011110000001010100100001100110101000100111010100001110001010100110011100100110111011001010011010010110001000001000111010011100001011110000000001101111001101011110100010111101111101100101010101110100010000111111100001110001101111010110011001010100011010110000110011011111111001011111000001010011100101010100001101010110100100101100000111001001101110000000000110010111100010011000010010010000011110011010101111011110111000001001011000110000101001001001110000100111001001101000011110011011101100'

if host == "localhost": # debug check
    from challenge import HASH, FLAG
    R_ = Random(int(HASH(FLAG).hex(), 16))
    assert int(bitstream, 2) == R_.GetRandBits(800)


# go to brute_seed.py to recover the needed seed
username = B64Enc(921205744651925343)
login(r, username, enc=False)
print(pull(r))
