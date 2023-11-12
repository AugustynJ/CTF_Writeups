# Cake CTF 2023

> Welcome to CakeCTF 2023! CakeCTF 2023 is a Jeopardy-style Capture The Flag competition hosted by yoshiking, theoremoon, and ptr-yudai. There will be challenges in categories such as pwn, web, rev, crypto, etc. The challenges are of a difficulty level targeting beginner to intermediate players.
This year we have reduced the difficulty level and the number of challenges a little more than in previous years. Advanced players are encouraged to participate solo or in teams with a couple of people.
>
## simple signature

The task starts with server code:
```python
import os
import sys
from hashlib import sha512
from Crypto.Util.number import getRandomRange, getStrongPrime, inverse, GCD
import signal


flag = os.environ.get("FLAG", "neko{cat_does_not_eat_cake}")

p = getStrongPrime(512)
g = 2


def keygen():
    while True:
        x = getRandomRange(2, p-1)
        y = getRandomRange(2, p-1)
        w = getRandomRange(2, p-1)

        v = w * y % (p-1)
        if GCD(v, p-1) != 1:
            continue
        u = (w * x - 1) * inverse(v, p-1) % (p-1)
        return (x, y, u), (w, v)


def sign(m, key):
    x, y, u = key
    r = getRandomRange(2, p-1)

    return pow(g, x*m + r*y, p), pow(g, u*m + r, p)


def verify(m, sig, key):
    w, v = key
    s, t = sig

    return pow(g, m, p) == pow(s, w, p) * pow(t, -v, p) % p


def h(m):
    return int(sha512(m.encode()).hexdigest(), 16)


if __name__ == '__main__':
    magic_word = "cake_does_not_eat_cat"
    skey, vkey = keygen()

    print(f"p = {p}")
    print(f"g = {g}")
    print(f"vkey = {vkey}")

    signal.alarm(1000)

    while True:
        choice = input("[S]ign, [V]erify: ").strip()
        if choice == "S":
            message = input("message: ").strip()
            assert message != magic_word

            sig = sign(h(message), skey)
            print(f"(s, t) = {sig}")

        elif choice == "V":
            message = input("message: ").strip()
            s = int(input("s: ").strip())
            t = int(input("t: ").strip())

            assert 2 <= s < p
            assert 2 <= t < p

            if not verify(h(message), (s, t), vkey):
                print("invalid signature")
                continue

            print("verified")
            if message == magic_word:
                print(f"flag = {flag}")
                sys.exit(0)

        else:
            break
```

And the connection socket - `nc crypto.2023.cakectf.com 10444`.

During analysis we realize that there's so many random values that we couldn't recreate. We assume that we have to deal with this flag withous cracking `skey` value.

The values that we know and are possible to use: $p, g=2, vkey = (w, v) $ and modular inversions of some of them.

As we can see, function `verify` we can write as: $g^{m} = s^{w} \cdot t^{-v}  \mod p$, where $s, t$ are powers of $g$ too. And the goal is to get $s, t$ values for `m = 'cake_does_not_eat_cat'`, which we cannot get from signing that message. Because of `sha512` any type of guessing or bruteforce is sensless. 

So what's the point? The solve is `inverse` function. Because of we know $skey = (w, v)$ values and we know from the content of challenge that $w, v \bot p$, so we can calculate their modular inversions.

But why? Look, if we couldn't calculate $s, t$ values for `magic_word` we will prepare it ourselves. We know that $s = g^x $ and $t = g^y$ for inteeger $x, y$. Now, function `verify` looks like:  $g^{m} = g^{x^w} \cdot g^{y^{-v}}  \mod p$. 

Base is $g$, so we can focus only on exponents: $m = x\cdot w + y\cdot (-v) \mod (p-1)$, where we can determine $x, y$ values. For example they could be: $x = (m-1)\cdot w^{-1} \mod (p-1)$ and $y = (-v)^{-1} \mod (p-1)$.

And they we have it! It is true equation, because:

$$m = x\cdot w + y\cdot (-v) =  (m-1)\cdot w^{-1}\cdot w + (-v)^{-1}\cdot (-v) = (m-1) + 1 = m \mod p$$

There's code with solution:
```python
# nc crypto.2023.cakectf.com 10444
from pwn import *
from hashlib import sha512
from Crypto.Util.number import inverse


def h(m):
    return int(sha512(m.encode()).hexdigest(), 16)


HOST = 'crypto.2023.cakectf.com'
PORT = 10444
magic_word = "cake_does_not_eat_cat"


io = remote(HOST, PORT)
line = io.recvline().decode().split()
p = int(line[2])
io.recvline()
g = 2
line = io.recvline().decode().split()
vkey = int(line[2][1:-1]), int(line[3][:-1])
w, v = vkey

s = pow(g, (h(magic_word) - 1) * inverse(w, (p-1)), p)
t = pow(g, inverse(-v, (p-1)), p)

io.recvuntil(b'[S]ign, [V]erify: ')
io.sendline(b'V')
io.recvuntil(b'message: ')
io.sendline(magic_word.encode())
io.recvuntil(b's: ')
io.sendline(str(s).encode())
io.recvuntil(b't: ')
io.sendline(str(t).encode())
if io.recvline().decode().strip() == 'verified':
    print(io.recvline().decode().strip())
```

With output: **flag = CakeCTF{does_yoshiking_eat_cake_or_cat?}**