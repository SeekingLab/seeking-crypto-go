Pure elgamal cryptosystem implemented in Go

Reference from https://en.wikipedia.org/wiki/ElGamal_encryption

ElGamal encryption consists of three components: the key generator, the encryption algorithm, and the decryption algorithm.

#Key generation

The first party, Alice, generates a key pair as follows:

Generate an efficient description of a cyclic group G, of order q, with generator g. Let e represent the unit element of G.
Choose an integer x randomly from {1,...,q-1}.
Compute h:=g^{x}.
The public key consists of the values (G,q,g,h). Alice publishes this public key and retains x as her private key, which must be kept secret.


#Encryption

A second party, Bob, encrypts a message M to Alice under her public key (G,q,g,h) as follows:

Map the message M to an element m of G using a reversible mapping function.
Choose an integer y randomly from {1,...,q-1}.
Compute s:=h^{y}. This is called the shared secret.
Compute c_{1}:=g^{y}.
Compute c_{2}:=m \cdot s.
Bob sends the ciphertext (c_{1},c_{2}) to Alice.
Note that if one knows both the ciphertext (c_{1},c_{2}) and the plaintext {\displaystyle m}m one can easily find the shared secret s, since c_{2}\cdot m^{-1}=s}. Therefore, a new y and hence a new s is generated for every message to improve security. For this reason, y is also called an ephemeral key.

#Decryption

Alice decrypts a ciphertext (c_{1},c_{2}) with her private key x as follows:

Compute s:=c_{1}^{x} . Since c_{1}=g^{y},  c_{1}^{x}=g^{xy}=h^{y} and thus it is the same shared secret that was used by Bob in encryption.
Compute s^{-1} , the inverse of s in the group G. This can be computed in one of several ways. If G is a subgroup of a multiplicative group of integers modulo n, the modular multiplicative inverse can be computed using the Extended Euclidean Algorithm. An alternative is to compute s^{-1} as c_{1}^{q-x}. This is the inverse of s because of Lagrange's theorem, since s\cdot c_{1}^{q-x}=g^{xy}\cdot g^{(q-x)y}=(g^{q})^{y}=e^{y}=e.
Compute m:=c_{2}\cdot s^{-1}. This calculation produces the original message m, because c_{2}\cdot s^{-1}=(m\cdot s)\cdot s^{-1}=m\cdot e=m}.
Map m back to the plaintext message M.


