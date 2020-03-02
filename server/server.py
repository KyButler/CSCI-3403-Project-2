"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Kyran Butler
    John Salame
	In Ji Chung
"""

import socket, hashlib, binascii, os, time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import base64

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function

    #This key was not necessary, just for testing
    f = open("RSA_keys", "r")
    key = f.read().split("-", 13)[10] # gets just the key part
    #print(key)
    f.close()

    #John's additions
    priv_key = RSA.importKey(open('RSA_keys').read())
    cipher = PKCS1_OAEP.new(priv_key)
    decrypted_key = cipher.decrypt(session_key)
    print("AES KEY: ", decrypted_key)
    return decrypted_key


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key, iv):
    aes = AES.new(session_key, AES.MODE_CBC, iv) #Init AES
    cipher = aes.decrypt(client_message)
    #print(cipher)
    return cipher


# Encrypt a message using the session key
def encrypt_message(message, session_key, iv):
    aes = AES.new(session_key, AES.MODE_CBC, iv) #Init AES
    ciphertext = aes.encrypt(pad_message(message)) # Encrypt message
    return ciphertext


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password
                # uses same method as in add_user
                #print("Salt: ", line[1])
                salt = line[1] #this is a string
                salt = salt[2:-1] #get rid of b''
                #print("Salt without b'': ", salt)
                salt = salt.encode('ascii') #turn string into bytes
                #print(salt)
                #hashed_password adapted from add_user.py
                hashed_password = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
                #print(hashed_password)
                #print(binascii.unhexlify(line[2][2:-1])) #turn string into binary data
                return hashed_password == binascii.unhexlify(line[2][2:-1])
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)
                #print("ciphertext!", ciphertext_message)
                iv = receive_message(connection)
                #print("iv", iv)

                # TODO: Decrypt message from client
                decryptedMessage = decrypt_message(ciphertext_message, plaintext_key, iv)
                print (decryptedMessage)

                # TODO: Split response from user into the username and password
                #John section: verify user
                decryptedMessage = decryptedMessage.decode("ASCII")
                #print(decryptedMessage)
                upass = decryptedMessage.split(' ', 2)
                user = upass[0]
                password = upass[1]
                #print(user)
                #print(password)
                valid_user = verify_hash(user, password)

                # TODO: Encrypt response to client
                response_iv = os.urandom(16) # 128 bit IV init
                #print(response_iv)
                plaintext_response = ""
                if valid_user:
                    plaintext_response = "User validated!"
                else:
                    plaintext_response = "Invalid user or password!"
                ciphertext_response = encrypt_message(plaintext_response, plaintext_key, response_iv)

                # Send encrypted response
                send_message(connection, ciphertext_response)
                time.sleep(0.1) #wait 0.1 seconds
                send_message(connection, response_iv)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
