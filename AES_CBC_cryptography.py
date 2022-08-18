###################################################
#             AES CBC Cryptography              #
###################################################

from os import urandom
from Crypto.Cipher import AES
import time

#start time
st = time.process_time()

# CBC MODE
MODE_CBC = 2

#Define blocksize
BLOCK_SIZE = 16
 
# key size must be 16 or 32
key = urandom(16)
#key = b'I_am_32bytes=256bits_key_padding'
print(key)
 
data = 'This is AES cryptography'
print('Raw Data:', data)

# Padding plain text with space 
pad = BLOCK_SIZE - len(data) % BLOCK_SIZE
data = data + " "*pad
 
# Generate iv with HW random generator 
iv = urandom(BLOCK_SIZE)
cipher = AES.new(key, MODE_CBC, iv)
 
encrypted = cipher.encrypt(data.encode('utf8'))
print ('\nEncrypted Data:', encrypted)
 
#iv = encrypted[:BLOCK_SIZE]
revcipher = AES.new(key,MODE_CBC,iv)
decrypted = revcipher.decrypt(encrypted)
print('\nDecrypted Data:', decrypted)

# get the end time
et = (time.process_time() - st)

print('\nExecution time:', et-st, 'seconds')
