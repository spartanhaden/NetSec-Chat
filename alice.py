#!/usr/bin/env python

import socket
import binascii
import threading
import time
from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits
from tkinter import *

port = 8671
kdc_port = 8888
ip = '127.0.0.1'
bob_address = (ip, port)

alices_key = b'23FCE5AE61E7BFCB29AC85725E7EC77DB9DBA460EACA7458070B719CE0B1DC31'

user_queue = []
alice_queue = ['Hello alice, welcome to chat']


def encrypt(key, data):
    # Setup the cipher to encrypt the data
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_SIV)

    # Encrypt the data
    ciphertext, digest = cipher.encrypt_and_digest(data)

    # Convert to ascii to comply with assignment description
    ascii_ciphertext = binascii.hexlify(ciphertext)
    ascii_digest = binascii.hexlify(digest)

    # Concatenate the ciphertext and digest
    return ascii_ciphertext + b'-' + ascii_digest


def decrypt(key, data):
    # Setup the cipher to decrypt the data
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_SIV)

    # Split the ciphertext from the digest
    ascii_ciphertext, ascii_digest = data.split(b'-')

    # Decrypt the message
    return cipher.decrypt_and_verify(binascii.unhexlify(ascii_ciphertext), binascii.unhexlify(ascii_digest))


def setup_communication(sock, bob_address):
    # Send initial message to Bob
    print('Alice: Sending "Let\'s Talk" to Bob')
    sock.sendto('Let\'s talk'.encode(), bob_address)

    # Receive message back from Bob
    print('Alice: Waiting for nonce from Bob')
    bobs_encrypted_nonce = sock.recv(4096)

    # Send the message to the KDC
    alices_nonce_1 = getrandbits(32)
    print('Alice: Nonce received from Bob, messaging the KDC with nonce of ' + str(alices_nonce_1))
    kdc_message = str(alices_nonce_1).encode() + b' Alice Bob ' + bobs_encrypted_nonce
    sock.sendto(kdc_message, (ip, kdc_port))

    # Get a response from the KDC
    kdc_response = sock.recv(4096)
    print('Alice: Message received from the KDC')
    decrypted_kdc = decrypt(alices_key, kdc_response)
    kdc_split = decrypted_kdc.split()

    # Check if the message from the KDC is valid
    if kdc_split[0] != str(alices_nonce_1).encode() and kdc_split[1] == b'Bob':
        print('Alice: Alice\'s nonce not received back from KDC')
        exit()

    # Separate the session key and ticket
    session_key = kdc_split[2]
    ticket_for_bob = kdc_split[3]

    # Generate second nonce for Alice and send message to Bob
    alices_nonce_2 = getrandbits(32)
    encrypted_nonce_2 = encrypt(session_key, str(alices_nonce_2).encode())
    sock.sendto(ticket_for_bob + b' ' + encrypted_nonce_2, bob_address)
    print('Alice: Sent ticket to bob with new encrypted nonce of ' + str(alices_nonce_2))

    # Wait for the Alice's modified nonce and Bobs new nonce to come back from Bob
    encrypted_payload = sock.recv(4096)
    payload = decrypt(session_key, encrypted_payload).split()
    alices_nonce_2_modified = int(payload[0])
    bobs_nonce_2 = int(payload[1])
    print('Alice: Alice\'s modified nonce ' + str(alices_nonce_2_modified) + ' and Bob\'s nonce of ' + str(bobs_nonce_2) + ' were received from Bob')

    # Verify Alice's nonce has been modified properly
    if alices_nonce_2 - 1 != alices_nonce_2_modified:
        print('Alice: Alice\'s nonce was not modified properly')
        exit()

    # Modify, encrypt and send Bob's nonce back
    message = encrypt(session_key, str(bobs_nonce_2 - 1).encode())
    sock.sendto(message, bob_address)
    print('Alice: Sending Bobs updated nonce of ' + str(bobs_nonce_2 - 1))

    # Authentication completed
    return session_key


def handle_receiving(sock, session_key):
    while True:
        split_payload = sock.recvfrom(4096)[0].split()
        if len(split_payload) == 2:
            print('Message from ' + split_payload[0].decode())
            message = decrypt(session_key, split_payload[1])
            print(split_payload[0].decode() + ': ' + message.decode())
            user_queue.append(split_payload[0].decode() + ': ' + message.decode())


def handle_output():
    root = Tk()
    text = Text(root)
    text.pack()

    while True:
        #time.sleep(1)
        while len(alice_queue) > 0:
            text.insert(END, alice_queue.pop() + '\n')
        while len(user_queue) > 0:
            text.insert(END, user_queue.pop() + '\n')
        root.update_idletasks()
        root.update()


if __name__ == '__main__':
    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(60)

    # TODO Ask who the user wants to talk to, and what port they are at
    # TODO Use non blocking receive to kill program
    # TODO Remove timeout
    # TODO Have other user store port with KDC
    # TODO Dynamically generate session keys
    # TODO Make sure everything is commented

    #bob = input('Who would you like to talk to?')
    # Send name to KDC
    # KDC looks up who is
    # KDC returns ip
    # send nonce to them with request to Talk
    # maybe they have to say yes to send back Nonce

    session_key = setup_communication(sock, bob_address)

    # Create thread to listen for incoming messages
    threading.Thread(target=handle_receiving, args=(sock, session_key)).start()

    # Handle the message output
    threading.Thread(target=handle_output).start()

    while True:
        message = input().encode()
        if message == b'exit':
            exit()
        sock.sendto(b'alice ' + encrypt(session_key, message), bob_address)
        alice_queue.append('alice: ' + message.decode())
