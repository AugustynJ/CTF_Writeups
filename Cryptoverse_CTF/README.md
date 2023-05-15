# Cryptoverse 2023

Solutions for challenged passed by me.

> Cryptoverse CTF 2023 is a 36-hour CTF targeted at beginner to intermediate players
>
> The event will focus on cryptography, reverse engineering, and programming. 

## Warump 1

Something to do with this: `GmvfHt8Kvq16282R6ej3o4A9Pp6MsN`.

Looks like kind of `base` but not obvious.

After analyze in [CyberChef](https://gchq.github.io/CyberChef/) we can see that's base58 encoding with ROT13 (Caesar's substitution - rotate alphabet by 13).

![warump1](./images/warump1.png)

**cvctf{base58_with_rot}**

## Warump 2

> This cipher is invented by French cryptographer Felix Delastelle at the end of the 19th century.
>
> Ciphertext: `SCCGDSNFTXCOJPETGMDNG` Hint: `CTFISGODABEHJKLMNPQRUVWXY`
>
> Convert flag to lowercase. Add { and } to make it a valid flag format. No underscore is needed.

Felix Delastelle is author of many ciphers. In this case our key is [Bifid Cipher](https://en.wikipedia.org/wiki/Bifid_cipher). To solve this challenge I used [this](https://www.dcode.fr/bifid-cipher) useful website, where I used Hint as key. Why? It's text "CTF IS GOOD" and the rest of alphabet.

Let's decode!

![warump2](./images/warump2.png)

And after make-up with content of challenge we got him: **cvctf{funbifiddecoding}**

## Baby AES

