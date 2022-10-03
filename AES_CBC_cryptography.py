###################################################
#             AES CBC Cryptography              #
###################################################

from os import urandom
from Crypto.Cipher import AES
import time

#start time
st = time.perf_counter()

# CBC MODE
MODE_CBC = 2

#Define blocksize
BLOCK_SIZE = 16
 
# key size must be 16 or 32
#key = urandom(16)
key = b'I_am_32bytes=256bits_key_padding'
#print(key)
 
data = 'This is AES cryptography'
print('Raw Data:', data)

# Padding plain text with space 
pad = BLOCK_SIZE - len(data) % BLOCK_SIZE
data = data + "."*pad
 
# Generate iv with HW random generator
#iv = b'\xb54\xf4x\xa2\xd6\xab\x94\x03\x8a:k\xe3\x81\xad='
iv = urandom(BLOCK_SIZE)
cipher = AES.new(key, MODE_CBC, iv)
 
encrypted = cipher.encrypt(data.encode('utf8'))
print ('\nEncrypted Data:', encrypted)

#en = b'\x01\x1f\xd4\xe8\x94\xf4\x94{\x0b\x94\xdczy\xa3\xaa\xe19\xa5;\x8f\xbf\xc2\xe8\xf3Y\xf2\xf4\xd3\xf48\x966'
 
iv = encrypted[:BLOCK_SIZE]
revcipher = AES.new(key,MODE_CBC,iv)
decrypted = revcipher.decrypt(encrypted)
print('\nDecrypted Data:', decrypted)

# get the end time
#et = (time.perf_counter() - st)

print('\nExecution time:', et-st, 'seconds')
