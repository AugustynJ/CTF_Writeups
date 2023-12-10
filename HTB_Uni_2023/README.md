# HTB University CTF 2023

One of the most important CTF I've played with `lab4` team.

The challenge includes python server code (`83.136.255.41:36831`):

```python
import os, random, json
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import FLAG


class MSS:
    def __init__(self, BITS, d, n):
        self.d = d
        self.n = n
        self.BITS = BITS
        self.key = bytes_to_long(os.urandom(BITS//8))
        self.coeffs = [self.key] + [bytes_to_long(os.urandom(self.BITS//8)) for _ in range(self.d)]

    def poly(self, x):
        return sum([self.coeffs[i] * x**i for i in range(self.d+1)])

    def get_share(self, x):
        if x > 2**15:
            return {'approved': 'False', 'reason': 'This scheme is intended for less users.'}
        elif self.n < 1:
            return {'approved': 'False', 'reason': 'Enough shares for today.'}
        else:
            self.n -= 1
            return {'approved': 'True', 'x': x, 'y': self.poly(x)}
    
    def encrypt_flag(self, m):
        key = sha256(str(self.key).encode()).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(m, 16))
        return {'iv': iv.hex(), 'enc_flag': ct.hex()}

def show_banner():
    print("""
#     #  #####   #####               #       ###   
##   ## #     # #     #             ##      #   #  
# # # # #       #                  # #     #     # 
#  #  #  #####   #####     #    #    #     #     # 
#     #       #       #    #    #    #     #     # 
#     # #     # #     #     #  #     #   ## #   #  
#     #  #####   #####       ##    ##### ##  ###

This is a secure secret sharing scheme with really small threshold. We are pretty sure the key is secure...
    """)

def show_menu():
    return """
Send in JSON format any of the following commands.

    - Get your share
    - Encrypt flag
    - Exit

query = """


def main():
    mss = MSS(256, 30, 19)
    show_banner()
    while True:
        try:
            query = json.loads(input(show_menu()))
            if 'command' in query:
                cmd = query['command']
                if cmd == 'get_share':
                    if 'x' in query:
                        x = int(query['x'])
                        share = mss.get_share(x)
                        print(json.dumps(share))
                    else:
                        print('\n[-] Please send your user ID.')
                elif cmd == 'encrypt_flag':
                    enc_flag = mss.encrypt_flag(FLAG)
                    print(f'\n[+] Here is your encrypted flag : {json.dumps(enc_flag)}.')
                elif cmd == 'exit':
                    print('\n[+] Thank you for using our service. Bye! :)')
                    break
                else:
                    print('\n[-] Unknown command:(')
        except KeyboardInterrupt:
            exit(0)
        except (ValueError, TypeError) as error:
            print(error)
            print('\n[-] Make sure your JSON query is properly formatted.')
            pass

if __name__ == '__main__':
    main()
```

So wehave to guess 256-bit key using 19 queries to server. One of most important lines in program: `sum([self.coeffs[i] * x**i for i in range(self.d+1)])`.

What does it means? Well, it's kind of numeric system where base is $x$. Next information from there: `self.coeffs = [self.key] + [bytes_to_long(os.urandom(self.BITS//8)) for _ in range(self.d)]` meand that `coeffs[0] = key`. So from modular arithmetic: $$ key = poly(x) \mod x$$

That's a lot. With that knowledge we can use center-piece - [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem)! Using CRT we can solve this challenge. Why?
- Number of queries: 19
- Size of $x$ in query: 15 bits
- $19\cdot 15 = 285 > 256$
So there's big chance for guessing $key$ value. Fortunantely, python has prepared function in [sympy](https://www.geeksforgeeks.org/python-sympy-crt-method/) library

But remember! Modulus must be pairwise coprime. So to be secure - modulus would be only primes! To generate them I used `getPrime()` func from `pycrypto` library.

Queries must be in json format, but it's not a problem. After restoring key we have to decrypt flag using `AES.CBC` mode with padding. 

Full code of solution:

```python
from pwn import *
import json
from sympy.ntheory.modular import crt 
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from hashlib import sha256


HOST = "83.136.255.41"
PORT = 36831

prime_list = [
23399,
28591,
20549,
31153,
25391,
32297,
20807,
30509,
18269,
18119,
30059,
19609,
23039,
23509,
18539,
20477,
24889,
17903,
27043,
]


v = []
r = remote(HOST, PORT)
for x in prime_list:
    r.recvuntil(b'query =')
    q = {"command": "get_share"}
    q["x"] = x
    q = json.dumps(q)
    q = str(q) 
    r.sendline(q.encode())
    line = r.recvline().decode().strip()
    line = json.loads(line)
    shared = line["y"]
    v.append(int(shared))

key = crt(prime_list, v)[0]
key = sha256(str(key).encode()).digest()
r.recvuntil(b'query =')
q = {"command": "encrypt_flag"}
q = json.dumps(q)
r.sendline(q.encode())
r.recvuntil(b'Here is your encrypted flag : ')
line = r.recvline().decode().strip()
line = json.loads(line[:-1])
iv = int(line["iv"], 16)
iv = long_to_bytes(iv)
ct = int(line["enc_flag"], 16)
ct = long_to_bytes(ct)

cipher = AES.new(key, AES.MODE_CBC, iv)

flag = unpad(cipher.decrypt(ct), AES.block_size)
print(flag.decode())
```

And program gives us flag: **HTB{thr3sh0ld_t00_sm4ll_______CRT_t00_str0nk!}**