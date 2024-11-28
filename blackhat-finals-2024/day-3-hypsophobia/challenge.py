#!/usr/bin/env python3
import logging
#
# BlackHat MEA 2024 CTF Finals
#
# [Medium] Crypto - Hypsophobia
#

# Native imports
import os, base64
from typing import Tuple, List, Dict, Union
from secrets import randbelow

# Non-native dependencies
from Crypto.Util.number import getPrime, GCD, inverse     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Helper functions
def B64Encode(x: int) -> bytes:
    """ Encodes an integer into a url-safe base64 string. """
    return base64.urlsafe_b64encode(x.to_bytes(-(-x.bit_length()//8), 'big')).decode().strip('=')

def GenPrimes(pn: int, pl: int) -> Tuple[int, List[int]]:
    """ Generates a list of pn distinct pl-bit primes. """
    while True:
        ps = [getPrime(pl) for _ in range(pn)]
        if len(ps) == len(set(ps)):
            break
    n = 1
    for p in ps:
        n *= p
    return n, ps
    
def GenParams(bound: int, mod: int) -> Tuple[int, int]:
    """ Generates Weierstrass coefficients (a,b) over a field of size mod. """
    while True:
        a, b = [randbelow(int(bound)) for _ in '01']
        if 1 == GCD( 4 * a**3 + 27 * b**2, mod ):
            return a, b
        

# Challenge functions
def Elevator(x: int, floor: int, n: int, plan = {}) -> Tuple[int, Dict[int, int]]:
    """ Returns the value x taken to the floor-th floor. You know, like an elevator would. """
    if floor in plan:
        return plan[floor], plan
    if floor == 1:
        return x, { floor : x % n }
    u, plan = Elevator(x, floor // 2, n, plan = plan)
    if floor % 2:
        v, plan = Elevator(x, floor // 2 + 1, n, plan = plan)
        y = ((2 * (u * v + A) * (u + v) + 4 * B) * inverse(int(pow(v - u, 2, n)), n) - x) % n
        plan[floor] = y
        return y, plan
    y = ((pow(pow(u, 2, n) - A, 2, n) - 8 * B * u) * inverse(int(4 * (pow(u, 3, n) + A * u + B)), n)) % n
    plan[floor] = y
    return y, plan


# Challenge parameters
Pn = 64
Pl = 32
Up = (Pn * Pl) // 8

# Challenge set-up
HDR = r"""|
|                                      ___           
|                                     / _ \          
|   _   _ _  _  _  ___  _   __   ___ | |_) )_  __  __
|  | | | | || || |/ _ \| | /  \ / _ \|  _ <| |/  \/ /
|  | |_| | \| |/ ( (_) ) || || | (_) ) |_) ) ( ()  < 
|   \___/ \_   _/ \___/ \_   _/ \___/|  __/ \_)__/\_\
|           | |           | |        | |             
|           |_|           |_|        |_|             
|
|
|
|  [~] The FLAG is on the {}-th FLOOR, let's take the ELEVATOR up there ~ !""".format(Up**2)
print(HDR)

N, Ps = GenPrimes(Pn, Pl)
A, B  = GenParams(256, N)


logging.error(f"{N, A, B = }")


# Server loop
TUI = "|\n|  Menu:\n|    [G]o!\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input('|  > ').lower()

        # [Q]uit
        if choice == 'q':
            print('|\n|  [~] Goodbye ~ !\n|')
            break


        # [G]o!
        elif choice == 'g':
            print("|\n|  [~] Let's goooo ~ !!!")

            r = 1 + randbelow(256 - 1)
            s = 2 + randbelow(256 - 2)
            k = ((r << 8) + s) & 0xFFFE
            x = B64Encode(Elevator(int.from_bytes(FLAG, 'big'), k, N)[0])
            logging.error(int.from_bytes(FLAG, 'big'))

            if k == Up:
                print('|\n|  [~] Wow, the view up here is amazing. I can even see the flag ~ !')
                print('|    FLAG = {}'.format(FLAG.decode()))
            else:
                print("|\n|  [!] Nope sorry I can't go on any further... We got to floor {} but I feel sick and I... BLEUUUURGHHH{}".format(k, x))
                
            print("|\n|  [~] Let's go back down again...")


        else:
            print('|\n|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')

    except Exception as e:
        print('|\n|  [!] ERROR :: {}'.format(e))
