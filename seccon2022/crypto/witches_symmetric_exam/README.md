# SECCON 2022
Special thanks https://t.me/defkit, who helped me a lot in implementing this attack. We both watched the termination of this exploit for several hours.
## witches_symmetric_exam(197 pt, 22 solves)
Task description:
<pre>crypto witch made a exam. The exam has to communicate with witch and saying secret spell correctly. Have fun ;)<br>nc witches-symmetric-exam.seccon.games 8080</pre>
### Attachments:

```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flag import flag, secret_spell

key = get_random_bytes(16)
nonce = get_random_bytes(16)


def encrypt():
    data = secret_spell
    gcm_cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    gcm_ciphertext, gcm_tag = gcm_cipher.encrypt_and_digest(data)

    ofb_input = pad(gcm_tag + gcm_cipher.nonce + gcm_ciphertext, 16)

    ofb_iv = get_random_bytes(16)
    ofb_cipher = AES.new(key, AES.MODE_OFB, iv=ofb_iv)
    ciphertext = ofb_cipher.encrypt(ofb_input)
    return ofb_iv + ciphertext


def decrypt(data):
    ofb_iv = data[:16]
    ofb_ciphertext = data[16:]
    ofb_cipher = AES.new(key, AES.MODE_OFB, iv=ofb_iv)

    try:
        m = ofb_cipher.decrypt(ofb_ciphertext)
        temp = unpad(m, 16)
    except:
        return b"ofb error"

    try:
        gcm_tag = temp[:16]
        gcm_nonce = temp[16:32]
        gcm_ciphertext = temp[32:]
        gcm_cipher = AES.new(key, AES.MODE_GCM, nonce=gcm_nonce)

        plaintext = gcm_cipher.decrypt_and_verify(gcm_ciphertext, gcm_tag)
    except:
        return b"gcm error"

    if b"give me key" == plaintext:
        your_spell = input("ok, please say secret spell:").encode()
        if your_spell == secret_spell:
            return flag
        else:
            return b"Try Harder"

    return b"ok"


print(f"ciphertext: {encrypt().hex()}")
while True:
    c = input("ciphertext: ")
    print(decrypt(bytes.fromhex(c)))
```

The main idea behind the solution is literally padding oracle. We have <code>temp = unpad(m, 16)</code> part, which raises an error when padding is incorrect. Since the single block in AES OFB MODE is encrypted/decrypted like in AES ECB MODE, we can simply find all the decryptions and encryptions using this little fact.<br>
1. Find all the E(ofb_iv) using Padding Oracle attack. Hence we retrieve the encrypted data too.
2. After restoring <code>ofb_input</code>, we get padded <code>gc_tag + gcm_nonce + gcm_ciphertext</code>.
3. The AES GCM MODE works almost the same as the AES CTR mode, with a few significant differences:
    - IV(nonce), when it's not 92 bits(our case) is calculated using special GHASH function, which performs several calculations in GF(2**256)
    - The counter is not concatinated with the IV, but is added literally.
    - In addition to ciphertext, it produces the TAG(read signature), which is verified during decryption.
    - GHASH uses special H_k which is simply ECB(128 bit zero string) using the same key as in GCM.
4. We have to encrypt zero string to obtain H_k. This also can be done using Padding Oracle.
5. We have to decrypt GCM encrypted data, however it's decryption is literally applying ECB(OFB) encryption to the data, using GHASHE'd nonce. This nonce we have retrieved in step 2. Well, we have recovered the <code>spell</code>.
6. The final step is to compute the encryption and the tag of <code>give me key</code> string. All this can be done using:
    - Retrieved during the step 5 encrypted GCM IV's(we need only the zero and the first ones).
    - Retrieved during the step 4 H_k
    - Implemented GHASH function(I've not found any libs providing it, but ~~stole~~ borrowed the code from pycryptodome source code. It was a torture.
    - Retrieved during the step 1 encrypted OFB IV's to encrypt the data again using AES OFB.
7. Done. Now we input the spell and get our deserved flag.

<b>Remark</b><br>
It takes very long time to perform 6 padding oracle attacks. It took us about an hour to execute.
Also I was not able to repeat the attack after the CTF end, but I had the output from my attack, so I included it here, while testing the exploit locally.

```python
from pwn import remote
from time import time
import re
```

Borrowed from pycryptodome GHASH class:


```python
from Crypto.Util._raw_api import (
    load_pycryptodome_raw_lib,
    VoidPointer,
    create_string_buffer,
    get_raw_buffer,
    SmartPointer,
    c_size_t,
    c_uint8_ptr,
)

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util import _cpu_features
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad


# C API by module implementing GHASH
_ghash_api_template = """
    int ghash_%imp%(uint8_t y_out[16],
                    const uint8_t block_data[],
                    size_t len,
                    const uint8_t y_in[16],
                    const void *exp_key);
    int ghash_expand_%imp%(const uint8_t h[16],
                           void **ghash_tables);
    int ghash_destroy_%imp%(void *ghash_tables);
"""


def _build_impl(lib, postfix):
    from collections import namedtuple

    funcs = ("ghash", "ghash_expand", "ghash_destroy")
    GHASH_Imp = namedtuple("_GHash_Imp", funcs)
    try:
        imp_funcs = [getattr(lib, x + "_" + postfix) for x in funcs]
    except AttributeError:  # Make sphinx stop complaining with its mocklib
        imp_funcs = [None] * 3
    params = dict(zip(funcs, imp_funcs))
    return GHASH_Imp(**params)


def _get_ghash_clmul():
    """Return None if CLMUL implementation is not available"""

    if not _cpu_features.have_clmul():
        return None
    try:
        api = _ghash_api_template.replace("%imp%", "clmul")
        lib = load_pycryptodome_raw_lib("Crypto.Hash._ghash_clmul", api)
        result = _build_impl(lib, "clmul")
    except OSError:
        result = None
    return result

gsh_clmul = _get_ghash_clmul()

class _GHASH(object):
    """GHASH function defined in NIST SP 800-38D, Algorithm 2.
    If X_1, X_2, .. X_m are the blocks of input data, the function
    computes:
       X_1*H^{m} + X_2*H^{m-1} + ... + X_m*H
    in the Galois field GF(2^256) using the reducing polynomial
    (x^128 + x^7 + x^2 + x + 1).
    """

    def __init__(self, subkey, ghash_c):
        assert len(subkey) == 16

        self.ghash_c = ghash_c

        self._exp_key = VoidPointer()
        result = ghash_c.ghash_expand(c_uint8_ptr(subkey), self._exp_key.address_of())
        if result:
            raise ValueError("Error %d while expanding the GHASH key" % result)

        self._exp_key = SmartPointer(self._exp_key.get(), ghash_c.ghash_destroy)

        # create_string_buffer always returns a string of zeroes
        self._last_y = create_string_buffer(16)

    def update(self, block_data):
        assert len(block_data) % 16 == 0

        result = self.ghash_c.ghash(
            self._last_y,
            c_uint8_ptr(block_data),
            c_size_t(len(block_data)),
            self._last_y,
            self._exp_key.get(),
        )
        if result:
            raise ValueError("Error %d while updating GHASH" % result)

        return self

    def digest(self):
        return get_raw_buffer(self._last_y)
```

Сonvenient functions for communicating with the server:


```python
def params():
    msg = r.recvline()
    return re.findall(b"ciphertext: (.*)", msg)[0].decode()


def send(data):
    if isinstance(data, list):
        to_send = bytes(data).hex()
    elif isinstance(data, bytes):
        to_send = data.hex()
    elif isinstance(data, str):
        to_send = data
    r.sendline(to_send.encode())


def send_and_get_ans(data):
    r.recvuntil(b"ciphertext:")
    send(data)
    return r.recvline().decode()
```


```python
def recover_encrypted_block(block):
    print("Starting OFB padding oracle attack")

    if isinstance(block, bytes):
        block = list(block)

    counter = 1
    chosen_pt = [0] * 16
    for _ in range(16):
        for b in range(256):
            chosen_pt[16 - _ - 1] = b
            ans = send_and_get_ans(block + chosen_pt)
            if _ == 15 and "gcm" in ans:
                break
            if "gcm" in ans:
                for i in range(counter + 1):
                    chosen_pt[16 - 1 - i] ^= counter + 1
                    chosen_pt[16 - 1 - i] ^= counter
                print(f"Attacked {_+1}/{len(block)} bytes")
                counter += 1
                break
    for i in range(len(chosen_pt)):
        chosen_pt[i] ^= 0x10
    return bytes(chosen_pt)

def recover_needed_encrypted_ivs(ct, num=10):
    print("Started recovering first encrypted ivs")
    ivs = [recover_encrypted_block(ct[:16])]
    print(ivs)
    for _ in range(num):
        print("Started recovering iv" + str(_ + 1))
        ivs.append(recover_encrypted_block(ivs[-1]))

        print(f"Recovered iv{str(_+1)} {ivs[-1].hex()}")
    return b"".join(ivs)

def retrieve_encrypted_zeros():
    print("Started encrypting zeroes")
    enc_zeros = recover_encrypted_block(list(bytes.fromhex("0" * 32)))
    print("Found encrypted zeroes " + enc_zeros.hex())
    return enc_zeros
```


```python
def ghash(block, H_k):                                                          # ghash function
    ghash_c = gsh_clmul
    fill = (16 - (len(block) % 16)) % 16 + 8
    ghash_in = block + b"\x00" * fill + long_to_bytes(8 * len(block), 8)
    j0 = _GHASH(H_k, ghash_c).update(ghash_in).digest()
    return j0


def counter(IV, count):                                                         # adding counter to IV0
    return long_to_bytes(bytes_to_long(IV) + count)


def decrypt_spell(gcm_tag, nonce, ciphertext, zero_key):                        # spell decryption + retrieving gcm ivs
    spell = b""
    enc_ivs = []
    cipher_blocks = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
    print()
    print(len(cipher_blocks), cipher_blocks)
    print()
    initvector = ghash(nonce, zero_key)                                     # counter0

    iv0 = recover_encrypted_block(initvector)                    # encrypted counter0. Used only
                                                                                # in tag generation.
    enc_ivs.append(iv0)
    for n, ct in enumerate(cipher_blocks):
        round = n + 1
        iv = counter(initvector, round)
        enc_iv = recover_encrypted_block(iv)
        enc_ivs.append(enc_iv)
        R = min([len(enc_iv), len(ct)])
        plaintext = strxor(enc_iv[:R], ct[:R])
        spell += plaintext
        print(f"\nPartially decrypted spell: {spell}, part {n+1}/{len(cipher_blocks)}")
    return spell, enc_ivs


def get_tag_single_block(iv0, block, zero_key):                             # GCM tag generation procedure
    signer = _GHASH(zero_key, gsh_clmul)
    signer.update(block + b'\x00'*(16 - len(block)))
    signer.update(long_to_bytes(len(block) * 8, 16))                               # ct length
    tag = signer.digest()
    tag = strxor(tag, iv0)
    return tag


def final(enc_ivs, zero_key, nonce):                                              # GCM encryption
    plaintext = b"give me key"
    plaintext = plaintext

    enc_iv = enc_ivs[1]
    ciphertext = strxor(plaintext, enc_iv[:11])

    tag = get_tag_single_block(enc_ivs[0], ciphertext, zero_key)

    return pad(tag + nonce + ciphertext, 16)


def recover_gcm_ct(ivs, ofb_ct):
    ofb_ct = ofb_ct[16:]
    assert len(ivs) >= len(ofb_ct)
    return strxor(ofb_ct, ivs[:len(ofb_ct)])
```

Summing up:


```python
r = remote('witches-symmetric-exam.seccon.games', 8080)
ct = params()
print("___________________________________________________________")
print("Initial ciphertext: ", ct)
ct = bytes.fromhex(ct)

print("___________________________________________________________")
print("Start of recovering the encrypted OFB ivs and E(0^128)")
ivs  = recover_needed_encrypted_ivs(ct, (len(ct)-16)//16 - 1)
print("Recovered ofb ivs = ", ivs.hex())
print("___________________________________________________________")

enc_zero = retrieve_encrypted_zeros()

print("___________________________________________________________")
print("Start of recovering the GCM ciphertext output")
gcm_ct = recover_gcm_ct(ivs, ct)
print(f"Retrieved gcm_ct: {gcm_ct.hex()}")

gcm_tag, gcm_nonce, gcm_ct = gcm_ct[:16], gcm_ct[16:32], unpad(gcm_ct[32:],16)

print("___________________________________________________________")
print("Start of recovering the spell and encrypted GCM ivs")
spell, enc_ivs = decrypt_spell(gcm_tag, gcm_nonce, gcm_ct, enc_zero)

print("___________________________________________________________")
print(f"The spell is: {spell.decode()}")
print("___________________________________________________________")
print(enc_ivs, gcm_nonce)

payload = final(enc_ivs, enc_zero, gcm_nonce)
payload = ct.hex()[:32] + strxor(payload, ivs[:len(payload)]).hex()
r.sendline(payload.encode())
r.sendline(spell)
m = r.recvuntil(b'spell:')
flag = r.recvline()
r.close()
```

    [x] Opening connection to witches-symmetric-exam.seccon.games on port 8080
    [x] Opening connection to witches-symmetric-exam.seccon.games on port 8080: Trying 153.127.198.221
    [+] opening connection to witches-symmetric-exam.seccon.games on port 8080: done
    ___________________________________________________________
    Initial ciphertext: c16dc68c8167eaeb204078b63072cde3cf3c066c5823a361a7867f01fd2f7463e1687093a1cfac93b65db72f916693237ee88684ffea595f644b380e085e820611d750849324f18cc7f2f20883304f97
    ___________________________________________________________
    Start of recovering the encrypted OFB ivs and E(0^128)
    Started recovering first encrypted ivs
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    Started recovering iv1
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    Recovered iv1 473883366ba295809b16fbb2dec81d81
    Started recovering iv2
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    Recovered iv2 6cb2bbcd3edc499c7283b4814dc189c7
    Started recovering iv3
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    Recovered iv3 8a1795d69b856eb8cffafa008b38479f
    recovered ofb ivs = 896da48748edeb14e8c32dfa65d6f04b473883366ba295809b16fbb2dec81d816cb2bbcd3edc499c7283b4814dc189c78a1795d69b856eb8cffafa008b38479f
    ___________________________________________________________
    Started encrypting zeroes
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    Found encrypted zeroes c6717a1a8ac6bc17d49c327ecfba6204
    ___________________________________________________________
    Start of recovering the GCM ciphertext output
    ___________________________________________________________
    Start of recovering the spell and encrypted GCM ivs
    
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    
    Partially decrypted spell: b'decrypt_all!!277', part 1/2
    Starting OFB padding oracle attack
    Attacked 1/16 bytes
    Attacked 2/16 bytes
    Attacked 3/16 bytes
    Attacked 4/16 bytes
    Attacked 5/16 bytes
    Attacked 6/16 bytes
    Attacked 7/16 bytes
    Attacked 8/16 bytes
    Attacked 9/16 bytes
    Attacked 10/16 bytes
    Attacked 11/16 bytes
    Attacked 12/16 bytes
    Attacked 13/16 bytes
    Attacked 14/16 bytes
    Attacked 15/16 bytes
    
    Partially decrypted spell: b'decrypt_all!!277260221!!', part 2/2
    ___________________________________________________________
    The spell is: decrypt_all!!277260221!!
    ___________________________________________________________
    [*] Stopped process './problem.py' (pid 627507)
    /home/sploit.py:184: byteswarning: text is not bytes; assuming ascii, no guarantees. see https://docs.pwntools.com/#bytes
      r.sendline(payload)
    [*] switching to interactive mode
    ciphertext: ok, please say secret spell:b'SECCON{you_solved_this!?i_g1ve_y0u_symmetr1c_cipher_mage_certificate}'



```python
print(flag)
```

    b'SECCON{you_solved_this!?I_g1ve_y0u_symmetr1c_cipher_mage_certificate}'

