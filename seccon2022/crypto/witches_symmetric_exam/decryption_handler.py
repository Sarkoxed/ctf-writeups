from pwn import remote, process
import re
import logging

logger = logging.Logger(__name__)
#r = remote('witches-symmetric-exam.seccon.games', 8080)
r = process("./problem.py")


def params():
    msg = r.recvline()
    return re.findall(b"ciphertext: (.*)", msg)[0].decode()


ct = params()
logger.warning("Found ct: " + ct)


def send(data):
    if type(data) == type([]):
        to_send = bytes(data).hex()
    elif type(data) == type(b""):
        to_send = data.hex()
    elif type(data) == type(""):
        to_send = data
    r.sendline(to_send.encode())


def send_and_get_ans(data):
    r.recvuntil(b"ciphertext:")
    send(data)
    return r.recvline().decode()


def _recover_encrypted_block_iv(iv):
    logger.info("Starting padding oracle ofb attack")
    if type(iv) == type(b""):
        iv = list(iv)
    counter = 1
    chosen_pt = [0] * 16
    for _ in range(16):
        for b in range(256):
            # print(str(b).zfill(3), end='\r')
            chosen_pt[16 - _ - 1] = b
            ans = send_and_get_ans(iv + chosen_pt)
            if _ == 15 and "gcm" in ans:
                break
            if "gcm" in ans:
                for i in range(counter + 1):
                    chosen_pt[16 - 1 - i] ^= counter + 1
                    chosen_pt[16 - 1 - i] ^= counter
                print(f"Attacked {_+1}/{len(iv)} bytes", end="\r")
                counter += 1
                break
    for i in range(len(chosen_pt)):
        chosen_pt[i] ^= 0x10
    return bytes(chosen_pt).hex()


def recover_needed_encrypted_ivs(num=10):
    logger.warning("Started recovering first encrypted iv")
    ivs = [_recover_encrypted_block_iv(list(bytes.fromhex(ct[:32])))]
    print(ivs)
    for _ in range(num):
        logger.warning("Started recover iv" + str(_ + 1))
        ivs.append(_recover_encrypted_block_iv(bytes.fromhex(ivs[-1])))
        logger.warning(f"Recovered iv{str(_+1)} {ivs[-1]}")
    logger.warning("Started encoding zeroes")
    enc_zeros = _recover_encrypted_block_iv(list(bytes.fromhex("0" * 32)))
    logger.warning("Found encrypted zeroes " + enc_zeros)
    return ivs, enc_zeros
