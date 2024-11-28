#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Finals
#
# [Hard] Crypto - GachaFlag
#
import logging

# Native imports
import os, hashlib, base64
from secrets import randbelow
from random import Random as _Random
from typing import List, Dict, Tuple

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()

    
# Global parameters
HASH = hashlib.sha256
FREE = 1000

DROPS = ['common', 'rare', 'epic', 'legendary', 'mythic']
DROP_TABLE = {}
DROP_TABLE['mythic']    = ( 2**32, lambda: FLAG.decode() ) 
DROP_TABLE['legendary'] = (   320, lambda: chr(FLAG[randbelow(len(FLAG))]) )
DROP_TABLE['epic']      = (    80, lambda: 'x' + FLAG.hex()[randbelow(len(FLAG)*2)] )
DROP_TABLE['rare']      = (    10, lambda: 'b' + str(int(0 != int.from_bytes(FLAG, 'big') & 2**randbelow(len(FLAG)*8))) )
DROP_TABLE['common']    = (  None, lambda: ' ' )


# Helper functions
def B64Enc(x: int) -> str:
    return base64.urlsafe_b64encode(x.to_bytes(-(-x.bit_length() // 8), 'big')).decode().strip('=')

def B64Dec(x: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(x.encode() + b'==='), 'big')


# Challenge classes
class Random(_Random):
    def __init__(self, seed: int) -> None:
        super().__init__(seed)
        self.buffer = ''
        self.saved_buffer = ''

    def GetRandBits(self, bits: int) -> int:
        while len(self.buffer) <= bits:
            self.buffer += '{:032b}'.format(self.getrandbits(32))
            self.saved_buffer += self.buffer[-32:]
        out, self.buffer = self.buffer[:bits], self.buffer[bits:]
        return int(out, 2)

class User:
    flag = True
    def __init__(self, username: str, flag=False) -> None:
        self.__srng = Random(int(HASH(FLAG).hexdigest(), 16))
        self.__urng = Random(B64Dec(username))
        self.__pulls = self.__GeneratePulls()
        #print(self.__pulls)
        self.left = len(self.__pulls)
        self.saved_buffer = self.__urng.saved_buffer
    
    def __Randint(self, a: int, b: int) -> int:
        u = b - a - 1
        while True:
            v = self.__srng.GetRandBits(u.bit_length())
            w = self.__urng.GetRandBits(u.bit_length())
            #if u == 9 and self.flag:
            #    logging.error(f"{v, w = }")
            #elif u == 2**32 - 1:
            #    logging.error(f"{v, w = }")
 
            x = (v + w) % (2 ** u.bit_length())
            logging.error(f"{v, w, x=}")
            if x <= u:
                break
        logging.error("_____________")
        return a + x
        
    def __GeneratePulls(self) -> List[int]:
        layers = []
        for drop in DROPS[1:]:
            pity = DROP_TABLE[drop][0]
            if pity < FREE:
                layer = []
                while len(layer) < FREE:
                    sub = [0] * pity
                    sub[self.__Randint(0, pity)] = DROPS.index(drop)
                    layer += sub
            else:
                layer = [0] * FREE
                t1 = self.__Randint(0, pity)
                logging.error(f"{t1 = }")
                try: layer[t1] = DROPS.index(drop)
                except: pass
            layers += [layer[:FREE]]
        return [max(i) for i in zip(*layers)]
    
    def Pull(self) -> Tuple[str, str]:
        pull = self.__pulls.pop(0)
        self.left -= 1
        return DROPS[pull], DROP_TABLE[DROPS[pull]][1]()


# Challenge set-up
HDR = r"""|
|
|   _______ _______ _______         _______
|  (  ____ \  ___  )  ____ \\     /|  ___  )
|  | (    \/ (   ) | (    \/ )   ( | (   ) |
|  | |     | (___) | |     | (___) | (___) |
|  | | ____|  ___  | |     |  ___  |  ___  |
|  | | \_  ) (   ) | |     | (   ) | (   ) |
|  | (___) | )   ( | (____/\ )   ( | )   ( |
|  (_______)/__ _ \|_______//__ __\|/__   \|
|      (  ____ \ \     (  ___  )  ____ \
|      | (    \/ (     | (   ) | (    \/
|      | (__   | |     | (___) | |
|      |  __)  | |     |  ___  | | ____
|      | (     | |     | (   ) | | \_  )
|      | )     | (____/\ )   ( | (___) |
|      |/      (_______//     \|_______)
|
|     What's more guessy than pure luck ?
|"""
#print(HDR)


# Server loop
TUI1 = "|\n|  Menu:\n|    [L]ogin"
TUI2 = "\n|    [S]inge pull\n|    [P]ull {}x"
TUI3 = "\n|    [Q]uit\n|"

user = None

if __name__ == "__main__":
    
    while True:
        try:
    
            if user and user.left:
                print(TUI1 + TUI2.format(user.left) + TUI3)
            else:
                print(TUI1 + TUI3)
            choice = input('|  > ').lower()
    
            # [Q]uit
            if choice == 'q':
                print('|\n|  [~] Goodbye ~ !\n|')
                break
    
    
            # [L]ogin
            elif choice == 'l':
    
                print('|\n|  [?] What is your username?')
                user = User(input('|  > (b64) '))
                logging.error(f"{user.saved_buffer}")
                print('|\n|  [~] Login successful ~ !')
    
            # [S]ingle pull
            elif choice == 's':
    
                rarity, pull = user.Pull()
                print("|\n|  [~] Congrats, you got a {} pull:\n|    pull = '{}'".format(rarity, pull))
    
            # [P]ull {}x
            elif choice == 'p':
    
                _, pulls = list(zip(*[user.Pull() for _ in range(user.left)]))
                print("|\n|  [~] Congrats, here are your rewards:\n|    pulls = '{}'".format(''.join(pulls)))
    
    
            else:
                print('|\n|  [!] Invalid choice.')
    
        except KeyboardInterrupt:
            print('\n|\n|  [~] Goodbye ~ !\n|')
    
        except Exception as e:
            print('|\n|  [!] ERROR :: {}'.format(e))
