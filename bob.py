#!/usr/bin/env python

import socket
import binascii
from Crypto.Cipher import AES
from Crypto.Random.random import getrandbits

server_address = '127.0.0.1'
server_port = 8671

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


if __name__ == '__main__':
    # Setup socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_address, server_port))
    print('Bob: Listening on ' + server_address + ':' + str(server_port))

    while True:
        # Waits for message from Alice
        print()
        print('Bob: waiting for request...')
        payload, client_address = sock.recvfrom(4096)

        # Receives first message from Alice and responds with an encrypted nonce
        if payload.decode() == 'Let\'s talk':
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
                continue

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
                continue

            # Wait for 'GET' from Alice
            encrypted_payload, client_address = sock.recvfrom(4096)
            payload = decrypt(session_key, encrypted_payload)
            if payload != b'GET':
                print('Bob: Message from Alice was not "GET" as expected')

            # Send file back
            in_file = open('ForAlice.txt', 'rb')
            data = in_file.read()
            in_file.close()
            message = encrypt(session_key, data)
            sock.sendto(message, client_address)
            print('Bob: Sent the file to Alice')
        else:
            print('Bob: Improper message received, please restart')
