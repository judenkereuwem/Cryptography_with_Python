
#pip install pycryptodome
#Encrypt and Decrypt data with RSA


from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import time

st = time.process_time()

key = RSA.generate(2048)
privateKey = key.exportKey('PEM')
publicKey = key.publickey().exportKey('PEM')

#print(privateKey)
#print(publicKey)

#Original message
message = b'This is a top secret message!'
#message = str.encode(message)
print("Original Text: ", message.decode('ascii'))

#Encryption
RSApublicKey = RSA.importKey(publicKey)
OAEP_cipher = PKCS1_OAEP.new(RSApublicKey)
encryptedMsg = OAEP_cipher.encrypt(message)
print("\nEncrypted text: ", encryptedMsg)

#Decryption
RSAprivateKey = RSA.importKey(privateKey)
OAEP_cipher = PKCS1_OAEP.new(RSAprivateKey)
decryptedMsg = OAEP_cipher.decrypt(encryptedMsg)
print("\nDecrypted text: ", decryptedMsg.decode('ascii'))

et = (time.process_time() - st)

print("\nTime: ", et-st, "sec.")
