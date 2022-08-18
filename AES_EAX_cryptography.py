
#Encrypt and Decrypt data with AES_AEX MODE

from Crypto.Cipher import AES
import time

st = time.process_time()

key = b'I_am_32bytes=256bits_key_padding'

data = b'This is a top secret message!'

print("Original : ", data.decode('ascii'))

#Encryption
cipher = AES.new(key, AES.MODE_EAX)
encrypted, tag = cipher.encrypt_and_digest(data)

print("Encrypted: ", encrypted)

file_out = open("encrypted.bin", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, encrypted) ]
file_out.close()


#Decryption
file_in = open("encrypted.bin", "rb")
nonce, tag, encrypted = [ file_in.read(x) for x in (16, 16, -1) ]

cipher = AES.new(key, AES.MODE_EAX, nonce)
decrypted = cipher.decrypt_and_verify(encrypted, tag)

print("Decrypted: ", decrypted.decode('ascii'))

et = (time.process_time() - st)

print("\nTime: ", et-st, "sec.")
