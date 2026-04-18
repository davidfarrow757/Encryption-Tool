import sys
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import hmac
from Crypto import Random
import hashlib

if len(sys.argv) != 4:
    print("[!] Invalid number of arguments")
    print("[!] Usage: python mini_encrypt.py ['encrypt' or 'decrypt'] [key file][target file]")
    exit(1)
_filename, action, rsa_key_file, target_file = sys.argv
if action == "encrypt": 
    # Encrypt and write the output to a file named message.encrypted
   
    #generate random AES key
    AES_key =  os.urandom(AES.block_size)

    #generate IV
    iv = Random.new().read(AES.block_size)

    #read text from file to data string
    text_file = open(sys.argv[3], "r")
    data = text_file.read() 
    data = data.encode('UTF-8')
    text_file.close()
    sizeofData = sys.getsizeof(data)

    #encrypt string: data as string: cipherData using AES
    cipher = AES.new(AES_key, AES.MODE_GCM, iv)
    cipherData, mac_tag = cipher.encrypt_and_digest(data)
    
    #encrypt the AES key with RSA public key
    publicKey = RSA.importKey(open(sys.argv[2]).read())
    cipher2 = PKCS1_OAEP.new(publicKey)
    cipherKey = cipher2.encrypt(AES_key)

    #create file named "message.encryted" 
    f = open('message.encrypted', 'wb')
    f.write(cipherKey)          #Output encrypted AES key
    f.write(iv)                             #Output iv 
    f.write(mac_tag)                       #Output mac 
    f.write(cipherData)                   #Output cipher
    f.close() 
elif action == "decrypt": 
    # Decrypt and print
    #read AES key, IV, MAC, and data from file
    myFile = open(sys.argv[3], 'rb')
    AES_key_from_file =  myFile.read(256)        #encrypted AES key
    iv_from_file = myFile.read(16)              #unencrypted iv
    mac_from_file = myFile.read(16)             #unencrypted mac
    data_from_file = myFile.read()            #encrypted data
    myFile.close()


    #Decrypt the AES key with RSA private key 
    privateKey = RSA.importKey(open(sys.argv[2]).read())
    cipher3 = PKCS1_OAEP.new(privateKey)
    unencrypted_AES_key = cipher3.decrypt(AES_key_from_file)

    #Use AES key to decrypt ciphertext. Generates a ValueError exception when tampering is detected.
    dCipher = AES.new(unencrypted_AES_key, AES.MODE_GCM, iv_from_file)
    plaintext = dCipher.decrypt_and_verify(data_from_file, mac_from_file) 

    #print plaintext to terminal
    plaintext = plaintext.decode('UTF-8')
    print("Message:\n")
    print(plaintext)
else:
    print(f"Invalid action '{action}', choose either 'encrypt' or 'decrypt'")
