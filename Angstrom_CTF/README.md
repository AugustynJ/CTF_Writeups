# ångstromCTF

>Welcome to ångstromCTF, a capture-the-flag (CTF) competition hosted and organized entirely by students at Montgomery Blair High School! CTF cybersecurity competitions have become an increasingly popular way for students to learn more about cybersecurity and develop and refine their hacking skills. These competitions are designed to educate and inspire high school students through interactive hacking challenges.

## Physics HW

> My physics teacher also loves puzzles. Maybe my [homework](./files/physics_hw.png) is a puzzle too?

Definitely our goal is not to solve all the physics questions on sheet of paper - it's miscellaneous challenge!

The flag is hidden inside (But `exiftool` is not adequate).

To deal with this I used [zsetg](https://github.com/zed-0xff/zsteg) - the best stegano tool I've ever used. How to use? simple as that:
```diff
$ zsteg -a physics_hw.png

-b1,rgb,lsb,xy       .. text: "actf{physics_or_forensics}"
b2,r,msb,xy         .. text: "_UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"
b2,g,msb,xy         .. text: "WUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU"
[...]
```

Under the flag there's milions of sensless signs, but the most importatnt is done: **actf{physics_or_forensics}**

## Impossible
`nc challs.actf.co 32200`

And [file](./files/impossible.py) in python version:

```python
#!/usr/local/bin/python

def fake_psi(a, b):
    return [i for i in a if i in b]

def zero_encoding(x, n):
    ret = []

    for i in range(n):
        if (x & 1) == 0:
            ret.append(x | 1)

        x >>= 1

    return ret

def one_encoding(x, n):
    ret = []

    for i in range(n):
        if x & 1:
            ret.append(x)

        x >>= 1

    return ret

print("Supply positive x and y such that x < y and x > y.")
x = int(input("x: "))
y = int(input("y: "))

if len(fake_psi(one_encoding(x, 64), zero_encoding(y, 64))) == 0 and x > y and x > 0 and y > 0:
    print(open("flag.txt").read())

```

Simple cryptography challenge. Let's solve in steps:

1. `len(fake_psi(...)) == 0) and x > y and x > 0 and y > 0` $\Rightarrow $ function `fake_psi` returns list of objects, so arguments must be zeros.
2. `one_encoding(x, 64)` must equals to $0$. In this case we interpret number in binary form. Something is on the `ret` (like return) list only if the last byte is set as $1$. But how much bytes? It's in $n$ parameter. At the end it removes the last byte. So if we want to get empty output we must submit $x$ number that has $n$ zeros in byte form at the end. In challenge $n=64$, so x that comply with requirements is e. g. $2^{64} = 18446744073709551616$
3. `zero_encoding(y, 64)` must equals to $0$ too. So let's analyze. It's similar to above, but now it appends something to `ret` list if last byte equals to $0$. So we need such $x$, that has $n$ last bytes equal to $1$. In the challenge case $n=64$, so solution can be $2^{64} - 1 = 18446744073709551615$

After submiting such numbers it gives us flag: **actf{se3ms_pretty_p0ssible_t0_m3_7623fb7e33577b8a}**

## Lazy Lagrange 

>Lagrange has gotten lazy, but he's still using Lagrange interpolation...or is he?

[File](./files/lazylagrange.py) that we start with:

```python
#!/usr/local/bin/python
import random

with open('flag.txt', 'r') as f:
	FLAG = f.read()

assert all(c.isascii() and c.isprintable() for c in FLAG), 'Malformed flag'
N = len(FLAG)
assert N <= 18, 'I\'m too lazy to store a flag that long.'
p = None
a = None
M = (1 << 127) - 1

def query1(s):
	if len(s) > 100:
		return 'I\'m too lazy to read a query that long.'
	x = s.split()
	if len(x) > 10:
		return 'I\'m too lazy to process that many inputs.'
	if any(not x_i.isdecimal() for x_i in x):
		return 'I\'m too lazy to decipher strange inputs.'
	x = (int(x_i) for x_i in x)
	global p, a
	p = random.sample(range(N), k=N)
	a = [ord(FLAG[p[i]]) for i in range(N)]
	res = ''
	for x_i in x:
		res += f'{sum(a[j] * x_i ** j for j in range(N)) % M}\n'
	return res

query1('0')

def query2(s):
	if len(s) > 100:
		return 'I\'m too lazy to read a query that long.'
	x = s.split()
	if any(not x_i.isdecimal() for x_i in x):
		return 'I\'m too lazy to decipher strange inputs.'
	x = [int(x_i) for x_i in x]
	while len(x) < N:
		x.append(0)
	z = 1
	for i in range(N):
		z *= not x[i] - a[i]
	return ' '.join(str(p_i * z) for p_i in p)

while True:
	try:
		choice = int(input(": "))
		assert 1 <= choice <= 2
		match choice:
			case 1:
				print(query1(input("\t> ")))
			case 2:
				print(query2(input("\t> ")))
	except Exception as e:
		print("Bad input, exiting", e)
		break
```

So what happened here?

From the first lines we realize that flag contains 18 signs. Next - there are two queries, the first returns us one number, the other one - list. 

The most important in `query1` is *for* loop:
```python
res += f'{sum(a[j] * x_i ** j for j in range(N)) % M}\n'
```
For each of sign is calculated weird sum: $a_j \cdot x_i \cdot j^N$, where $a$ - signs of flag, $x$ - your input $j \in {0, 1, 2, 3, ...}$ .

Seems like $x$-based numeric system. That's it! But be careful - output from `query1` is number MOD $2^{127} -1$, so the $x$ cannot be too large. Signs are in ascii format $\Rightarrow $ `ord(sign) < 128`.

The answer is send 128 to `query1` and decode it as 128-base number. Example decoder:

```python
def decode128(n):
    MOD = 128
    result = []
    while n > MOD:
        r = n % MOD
        result.append(r)
        n = (n-r) // MOD
    result.append(n)

    return result[::-1]
```

Final result: **actf{f80f6086a77b}**. Idk where is Lagrange reference.

Note: It's not only my solve - contributed by qualorm. Thank you for help!