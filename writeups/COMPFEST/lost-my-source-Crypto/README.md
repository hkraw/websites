# Lost-my-source - Crypto

- Guess first few bytes of key.

#### Wow this was guessy

#### Solution
```python
#!/usr/bin/python3
fencrypt = open("encrypted.txt","rb")
encrypted = fencrypt.read()
key = b"fedcba"+b"abcdefghijklmnopqrstuvwxyz"[::-1]
decrypted = ""
for fuck in range(31, -1, -1):
	decrypted += chr(encrypted[31-fuck] ^ fuck ^ key[fuck])
#COMPFEST12{Th1s_15_y0ur5_abcdef}
# WOw this was guessy :/
print(decrypted[::-1])
```

