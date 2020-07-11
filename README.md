# pki-example

The Public Key Infrastructure(PKI) is a comprehensive system to provide public key
encryption and digital signature services. PKI is used to manage keys and certificates for
maintaining a trustworthy networking environment. Public key encryption, or public key
cryptography, is a method of encrypting data with two different keys, private key and public
key. The public key is available for anyone to use and is shared. The other key is known
as the private key which is kept securely and is not shared. Data encrypted with the private
key can only be decrypted with the public key, and data encrypted with the public key can
only be decrypted with the private key. Public key encryption is also known as asymmetric
encryption. In our use case, the server uses separate private-public key pair for individual
clients. The client also needs to maintain the key pair on their side too. The private key is
used for signing or encrypting the message and public key is used to verify or decrypt the
message signed by their corresponding private key.

Note: The whitespace, newline and other special characters on the data section generates
different signature value. Therefore, please ensure no such characters are added while
constructing message
