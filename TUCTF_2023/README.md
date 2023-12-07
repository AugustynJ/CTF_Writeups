# TUCTF 2023

>TUCTF is an annual Capture the Flag competition hosted by the CTF club at the University of Tulsa.
>
>The 2023 TUCTF Competition is a jeopardy-style CTF designed for a range of skill levels. It will start at 12:00pm ET on Friday, December 1, 2023 and run for 48 hours until 12:00pm ET on Sunday, December 3, 2023.

## Keyboard cipher

We start only with number = `0x636a56355279424b615464354946686b566942794e586c4849455279523359674d47394d49486845643045675a316b315569426163304d675a316c715469426163314567616b6c7354534268563252594947745063434178643045675332395149466c6e536d343d`, and we don't know what to do. So the first thing - read as bytes!

```python
number = long_to_bytes(number)
print(number.decode())
```
`>>> cjV5RyBKaTd5IFhkViByNXlHIERyR3YgMG9MIHhEd0EgZ1k1UiBac0MgZ1lqTiBac1EgaklsTSBhV2RYIGtPcCAxd0EgS29QIFlnSm4=`

It seems like base64 encoding, so decode that!
```python
number = number.decode('utf-8')
number = base64.b64decode(number)
number = number.decode('utf-8')
print(number)
```
`>>> r5yG Ji7y XdV r5yG DrGv 0oL xDwA gY5R ZsC gYjN ZsQ jIlM aWdX kOp 1wA KoP YgJn`

And what's going on? It's called "keyboard cipher" so look at typical QWERTY keyboard. Every group of signs surrounds one letter - e. g. r5yG are around 't' letter. Similary, decoding other letters we got the flag (all lowercase) - **TUCTF{tuctfpstxhakslqlh}**