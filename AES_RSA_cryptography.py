
#Hybrid AES_RSA Cryptography

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import time

st = time.process_time()

#message
message = b'This is a top secret message'
print("Original : ", message.decode('ascii'))


#Generate RSA private and public key
key = RSA.generate(2048)
privateKey = key.exportKey('PEM')
publicKey = key.publickey().exportKey('PEM')
#print(privateKey)
#print(publicKey)


#Generate AES symmetric key
AES_key = b'I_am_32bytes=256bits_key_padding'
print("\nAES Key: ", AES_key.decode('ascii'))


#Encrypt message with AES key
cipher = AES.new(AES_key, AES.MODE_EAX)
encrypted, tag = cipher.encrypt_and_digest(message)

print("\nEncrypted Message: ", encrypted)

file_out = open("encrypted.bin", "wb")
[ file_out.write(x) for x in (cipher.nonce, tag, encrypted) ]
file_out.close()


#Encrypt AES key with RSA
RSApublicKey = RSA.importKey(publicKey)
OAEP_cipher = PKCS1_OAEP.new(RSApublicKey)
encryptedKey = OAEP_cipher.encrypt(AES_key)
#print("\nEncrypted AES Key: ", encryptedKey)



#Decrypt AES key with RSA
RSAprivateKey = RSA.importKey(privateKey)
OAEP_cipher = PKCS1_OAEP.new(RSAprivateKey)
decryptedKey = OAEP_cipher.decrypt(encryptedKey)
#print("\nDecrypted AES Key: ", decryptedKey.decode('ascii'))



#decrypt message with AES key
file_in = open("encrypted.bin", "rb")
nonce, tag, encrypted = [ file_in.read(x) for x in (16, 16, -1) ]

cipher = AES.new(AES_key, AES.MODE_EAX, nonce)
decrypted = cipher.decrypt_and_verify(encrypted, tag)

print("\nDecrypted Message: ", decrypted.decode('ascii'))

et = (time.process_time() - st)

print("\nTime: ", et-st, "sec.")















