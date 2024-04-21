
  SecureChannelBanking is a client and server program to provide a secure communication channel in the banking industry. These programs allow you to exchange encrypted messages between a client and a server, 
using symmetric and asymmetric encryption to ensure confidentiality and data integrity.

  Functionality

  Client program

- Generating an RSA key pair for the client
- Generation of a symmetric AES key for message encryption
- Establishing a secure connection with the server via a socket
- Public key exchange for asymmetric encryption
- Transfer of encrypted symmetric key over a secure connection
- Encrypt and send messages using a symmetric key
- Receive and decrypt encrypted messages from the server

  Server program

- Accepting connections from clients via socket
- Supports multiple client connections
- Transfer of encrypted messages between clients
