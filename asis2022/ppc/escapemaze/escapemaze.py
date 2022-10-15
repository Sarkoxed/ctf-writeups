#!/usr/bin/env python3
	
import random
import sys
from flag import flag
	
def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc(): 
	return sys.stdin.buffer.readline()
	
def main():
	nroom = 114
	xreq = nroom // 2 
	
	border = "|"
	pr(border*72)
	pr(border, f"Welcome to escape room! You are imprisoned in a maze with {nroom} doors.", border)
	pr(border, f"You have to unlock all doors to escape this maze and get the flag!! ", border)
	pr(border, f"An oracle is with you and can help you to find key of each door. The", border)
	pr(border, f"oracle has {nroom} keys with her. But the keys are shuffled. You can ask", border)
	pr(border, f"for a key from oracle {xreq - 1} times! If you can't find the key of each   ", border)
	pr(border, f"door you will be lost! For asking key, send a key number you want :)", border)
	pr(border*72)
	
	room = 1
	keys = list(range(1, nroom + 1))
	random.shuffle(keys)
	curr_salt = random.randint(0, 2**32)
	perv_salt = random.randint(0, 2**32)
	while (room <= nroom - 1):
		ntry = 0
		while(ntry < xreq - 1):
			curr_salt = random.randint(0, 2**32)
			pr(border, f"You are in room {room}, you can ask for {xreq - ntry - 1} other keys." )
			pr(border, "Enter a key number: ")
			inkey = sc()
			try:
				inkey = (int(inkey) % perv_salt) % nroom + 1
			except:
				die(border, "Your input key is not valid! Bye!!")
			pr(border, f"The requsted key is for room number {keys[(inkey-1) % perv_salt] + curr_salt}")
			ntry += 1
			if (keys[(inkey-1) % perv_salt]) == room:
				if room == nroom - 1:
					die(border, f"Great! You escaped! Here is your flag: {flag}")
				if room < nroom - 1:
					pr(border, "Great! You found key of this room. let's head into next one.")
					perv_salt = curr_salt
					room += 1
					break
			perv_salt = curr_salt
		if ntry == xreq - 1:
			pr(border, "Sorry! you couldn't find right key. You will be placed in first room!!!")
			room = 1
			keys = list(range(1, nroom + 1))
			random.shuffle(keys)
		
	
if __name__ == '__main__':
	main()
