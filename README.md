# zks


crs_gen(): This function generates an ElGamal key pair and a secret key (sk). It uses the curve25519_dalek library to generate a random elliptic curve point g and a random scalar sk. It then computes the public key h as the scalar sk multiplied by g. The function returns the public key pair (g, h) and the secret key sk.

rando(): This function takes a public key pair pk, a ciphertext pair c, and a scalar r as input. It performs an ElGamal re-encryption operation by adding scalar multiples of the public key elements to the ciphertext elements. It returns a new ciphertext pair.
rspeq_enc(): This function performs ElGamal encryption of a message m using a public key pair pk and a scalar r as randomness. It computes two ciphertext elements by multiplying the public key elements with the randomness and adding the message. The function returns the ciphertext pair.

rspeq_flow_1(): This function is the first step of the RSPEQ protocol. It takes two public key pairs pk0 and pk1, and two ciphertext pairs c0 and c1 as input. It generates two random scalars r_1 and r_2 and a random elliptic curve point rm. It uses the rando() function to perform re-encryption on the ciphertext pairs using the generated randomness and the corresponding public keys. The function returns the re-encrypted ciphertext pairs, the random point rm, and the random scalars r_1 and r_2.

rspeq_flow_2(): This function is the second step of the RSPEQ protocol. It returns a random boolean value using the random.getrandbits() function. The purpose of this step is to introduce randomness into the protocol.

rspeq_flow_3(): This function is the third step of the RSPEQ protocol. It takes a boolean value b and four random scalars r0, r_0, r1, and r_1 as input. If b is true, it returns the random scalars r_0 and r_1. Otherwise, it returns the sum of r0 and r_0 as well as the sum of r1 and r_1. This step combines randomness based on the boolean value.

rspeq_flow_4(): This function is the fourth step of the RSPEQ protocol. It takes several input parameters including a boolean value b, two public key pairs pk0 and pk1, two ciphertext pairs c0 and c_0, two ciphertext pairs c1 and c_1, and random scalars rx, ry, and a random point rm. Depending on the boolean value b, it performs re-encryption on the ciphertext pairs using the randomness and the corresponding public keys, and checks if the re-encrypted ciphertext pairs match the given ciphertext pairs c_0 and c_1. If b is false, it verifies an equality relation between the ciphertext pairs c_0 and c_1. The function returns a boolean value indicating the validity of the relation.

rspeq_key_init_test(): This function is a test function that checks the correctness of the key generation process. It generates a key pair using crs_gen() and verifies if the generated public key h matches the expected value based on the boolean flag should_succeed.

do_fast_test(): This function is another test function that performs a fast test of the RSPEQ protocol. It generates two key pairs, pk0 and pk1, and encrypts messages m0 and m1 using random scalars r0 and r1. It then executes the RSPEQ protocol steps multiple times, updating the values of variables and checking the validity of relations. The function returns a boolean value indicating the success or failure of the protocol execution.
