"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Kyran Butler
    John Salame
    In Ji Chung
"""

import socket
import os
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    key = os.urandom(16)
    print("AES KEY:")
    print(key)
    print("LENGTH ", len(key))
    return key # 128 bit key = 16 bytes


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    f = open("RSA_keys.pub", "r")
    printable_key = f.read().split(" ", 3)[1] # gets just the key part
    #print(printable_key)
    f.close()
    key = RSA.importKey(open("RSA_keys.pub").read())
    cipher = PKCS1_OAEP.new(key)
    encrypted_key = cipher.encrypt(session_key)
    #print(encrypted_key)
    return encrypted_key


def encrypt_message(message, session_key):
    iv = os.urandom(16) # 128 bit IV init
    print("iv", iv)
    print("key", session_key)
    aes = AES.new(session_key, AES.MODE_CBC, iv) #Init AES
    ciphertext = aes.encrypt(pad_message(message)) # Encrypt message
    print("ciphertext", ciphertext)
    dec = AES.new(session_key, AES.MODE_CBC, iv)
    cipher = dec.decrypt(ciphertext)
    print("cipher", cipher)
    return ciphertext


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function
    pass


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)
    pass

# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        send_message(sock, encrypt_message(message, key)) # check second argument's validity

        # TODO: Receive and decrypt response from server
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
