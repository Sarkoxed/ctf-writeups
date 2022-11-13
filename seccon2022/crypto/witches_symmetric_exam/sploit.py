from decryption_handler import _recover_encrypted_block_iv as __recover_encrypted_block_iv
from decryption_handler import ct,recover_needed_encrypted_ivs, r
from Crypto.Util._raw_api import (
    load_pycryptodome_raw_lib, VoidPointer,
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

_ghash_clmul = _get_ghash_clmul()

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


def get_ghash(nonce, enc_zero):
    ghash_c = _ghash_clmul
    fill = (16 - (len(nonce) % 16)) % 16 + 8
    ghash_in = nonce + b"\x00" * fill + long_to_bytes(8 * len(nonce), 8)
    j0 = _GHASH(enc_zero, ghash_c).update(ghash_in).digest()
    return j0


def get_counter(nonce, count):
    return long_to_bytes(bytes_to_long(nonce) + count)


# _recover_encrypted_block_iv


def decrypt_ciphertext(gcm_tag, nonce, ciphertext, zero_key):
    spell = b""
    enc_ivs = []
    ciphertexts = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
    initvector = get_ghash(nonce, zero_key)

    zero_enc = bytes.fromhex(__recover_encrypted_block_iv(initvector))
    enc_ivs.append(zero_enc)

    for i, j in enumerate(ciphertexts):
        round = i + 1
        iv = get_counter(initvector, round)
        enc_iv = bytes.fromhex(__recover_encrypted_block_iv(iv))
        enc_ivs.append(enc_iv)
        R = min([len(enc_iv), len(j)])
        plaintext = strxor(enc_iv[:R], j[:R])
        spell += plaintext
        print(spell)
    return spell, enc_ivs


def win(enc_ivs, zero_key, nonce):
    plaintext = b"give me key"
    plaintext = plaintext
    
    enc_iv = enc_ivs[1]
    ciphertext = strxor(plaintext, enc_iv[:11])

    signer = _GHASH(zero_key, _ghash_clmul)
    signer.update(ciphertext + b'\x00'*5)
    signer.update(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58')
    tag = signer.digest()
    tag = strxor(tag, enc_ivs[0])

    return pad(tag + nonce + ciphertext,16)



def recover_gcm_ct(ivs,ofb_ct):
    iv = bytes(b''.join(bytes.fromhex(i) for i in ivs))
    ofb_ct = bytes.fromhex(ofb_ct)[16:]
    print(len(ofb_ct), len(iv))
    assert len(iv) >= len(ofb_ct)
    return strxor(ofb_ct, iv[:len(ofb_ct)])
import logging 
logger = logging.Logger(__name__)
def main():
    logger.warning("Start of recovering of encrypted ivs and E(0^128)")
    ivs, enc_zeros = recover_needed_encrypted_ivs((len(ct)-32)//32 - 1)
    print("Recovered ofb ivs = " + "".join(ivs))
    logger.warning("Start of recovering of gcm ciphertext output")
    gcm_ct = recover_gcm_ct(ivs,ct)
    gcm_tag, gcm_nonce, gcm_ct = gcm_ct[:16], gcm_ct[16:32], unpad(gcm_ct[32:],16)
    logger.warning("Start of recovering of spell and encrypted GCM ivs")
    spell, enc_ivs = decrypt_ciphertext(gcm_tag, gcm_nonce,gcm_ct, bytes.fromhex(enc_zeros))
    print(f"The spell is: {spell}")
    print(enc_ivs, gcm_nonce)
    payload = win(enc_ivs, bytes.fromhex(enc_zeros), gcm_nonce)
    payload = ct[:32] + strxor(payload, bytes.fromhex("".join(ivs))[:len(payload)]).hex()
    #payload = ct[:32] + payload.hex()
    #print(ct[:32] + payload.hex())
    r.sendline(payload)
    r.sendline(spell)
    r.interactive()


if __name__ == "__main__":
    main()
