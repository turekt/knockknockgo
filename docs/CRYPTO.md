# Cryptography in knockknockgo

At the time of writing, the situation with knockknockgo is as follows.

We can extract the following fields from the IPv4 packet (limited by firewall log):
  - ID     (2 bytes)
  - SEQ    (4 bytes)
  - ACK    (4 bytes)
  - WINDOW (2 bytes)
  - SPT    (2 bytes)
and from the IPv6 packet (limited by firewall log):
  - FLOWLBL(2 bytes) - ok, 20 bits actually
  - SEQ    (4 bytes)
  - ACK    (4 bytes)
  - WINDOW (2 bytes)
  - SPT    (2 bytes)
Making it a total of 14 bytes of encrypted data that can be transfered to the server.

## Enter stream ciphers

In contrast to AES block ciphers, AES-GCM and ChaCha20-Poly1305 are stream ciphers.

Stream ciphers are more suitable for the case here because:
- TCP port number is always going to be exactly 2 bytes
- AES-CTR and ChaCha20 will output ciphertext of size which is the same as plaintext (2 bytes)
- GCM and Poly1305 used in conjuction with AES and ChaCha20 for authentication of ciphertext, respectively, produces a tag of size 16 bytes (128 bits)

If we agree on deriving nonce from a 2 byte counter and preshared nonce "salt", we can use:
- 2 bytes  - nonce
- 2 bytes  - ciphertext
- 10 bytes - tag (out of 16, more than half is verified)

The only risk here is that nonce 2 byte pool can get depleted (max 65535 nonce in pool or shorter if client introduces a greater value than in configuration) and nonces can get repeated for that assigned port which is not good. In that case it would be best to execute a rekey of that port, which should be easy with knockknockgo:
```
kkd gen -profiles PROFILES_DIR -port PORT_NUM
```

## Encryption procedure and verification

Nonce is an unsigned integer which is stretched with key derivation function PBKDF2 using SHA3-512. Each port is configured with a random nonce salt which is supplied to PBKDF2. Derived nonce bytes of nonce size are supplied along with port 2-byte representation to the seal function of the AEAD cipher. The resulting ciphertext is prefixed with a 2-byte nonce in order for the second party to be able to derive the nonce bytes after they are sent over the wire.

To verify, the receiving party checks the port number and 12 bytes of ciphertext. The ciphertext received is never decrypted. The port number is encrypted using the same procedure as mentioned above and 12 bytes of received ciphertext is compared with the given ciphertext calculated after repeating the encryption procedure. In case ciphertexts are the same, the client is verified and port is opened.
