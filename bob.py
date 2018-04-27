#!/usr/bin/env python

import socket
import binascii
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random.random import getrandbits

server_address = '127.0.0.1'
server_port = 8671
kdc_port = 8888

bobs_key = b'A41503A5D9E66B34FAC9F2FC9FD14CA24D728B17DE0FCC2C3676DED6A191A1F1'


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


def register_with_kdc(sock, name):
    # Ask the KDC for it's public key
    sock.sendto(b'request_public_key', (server_address, kdc_port))
    payload = sock.recvfrom(4096)[0]

    # Use the KDC's public key to encrypt the user's key
    public_key = RSA.import_key(payload)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_user_key = cipher_rsa.encrypt(bobs_key)

    # Register with the KDC
    sock.sendto(b'add_user ' + name.encode() + b' ' + binascii.hexlify(enc_user_key), (server_address, kdc_port))


def setup_communication(sock, client_address):
    bobs_nonce_1 = getrandbits(32)
    print('Bob: Let\'s talk received, sending ' + str(bobs_nonce_1) + ' as the nonce')
    message = encrypt(bobs_key, str(bobs_nonce_1).encode())
    sock.sendto(message, client_address)

    # Wait for Alice to get the session key from the KDC
    payload, client_address = sock.recvfrom(4096)
    print('Bob: Ticket and encrypted nonce received from Alice')

    # Break apart the message from Alice
    encrypted_ticket, alices_encrypted_nonce_2 = payload.split()
    ticket = decrypt(bobs_key, encrypted_ticket)
    split_ticket = ticket.split()
    session_key = split_ticket[0]

    # Verify the ticket
    if split_ticket[1] != b'Alice' and decrypt(bobs_key, split_ticket[2]) != str(bobs_nonce_1).encode():
        print('Bob: Ticket from Alice is invalid')
        exit()

    # Decrypt Alices second nonce and increment it
    alices_nonce_2 = int(decrypt(session_key, alices_encrypted_nonce_2))
    print('Bob: Decrypted Alice\'s nonce and found ' + str(alices_nonce_2))
    alices_nonce_2 -= 1

    # Create bob's second nonce, encrypts it with Alice's and sends it back
    bobs_nonce_2 = getrandbits(32)
    message = str(alices_nonce_2).encode() + b' ' + str(bobs_nonce_2).encode()
    sock.sendto(encrypt(session_key, message), client_address)
    print('Bob: Sent Bob\'s new nonce of ' + str(bobs_nonce_2) + ' and Alice\'s modified nonce of ' + str(alices_nonce_2))

    # Wait for Bobs modified nonce to come back from Alice
    encrypted_payload, client_address = sock.recvfrom(4096)
    bobs_nonce_2_modified = int(decrypt(session_key, encrypted_payload).decode())
    print('Bob: Bob\'s modified nonce ' + str(bobs_nonce_2_modified) + ' received from Alice')

    # Verify the modified nonce from alice
    if bobs_nonce_2 - 1 != bobs_nonce_2_modified:
        print('Bob: Bob\'s nonce was not modified properly')
        exit()

    # Authentication completed
    return session_key


def handle_receiving(sock, session_key):
    split_payload = sock.recvfrom(4096).split()
    if len(split_payload) == 2:
        print('Message from ' + split_payload[0].decode())
        message = decrypt(session_key, split_payload[1])
        print(split_payload[0].decode() + ': ' + message)


if __name__ == '__main__':
    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    sock.bind((server_address, server_port))
    print('Bob: Listening on ' + server_address + ':' + str(server_port))

    #name = input('What is your name?')
    name = 'bob'
    register_with_kdc(sock, name)

    # Waits for message from Alice
    print()
    print('Bob: waiting for request...')
    payload, client_address = sock.recvfrom(4096)

    # Receives first message from Alice and responds with an encrypted nonce
    if payload.decode() == 'Let\'s talk':
        session_key = setup_communication(sock, client_address)
    else:
        print('Bob: Improper message received, please restart')
        exit()

    # Create thread to listen for incoming messages
    threading.Thread(target=handle_receiving, args=(sock, session_key)).start()

    while True:
