from charm.toolbox.pairinggroup import PairingGroup, ZR, G1
import random

# Generate key pair
def crs_gen():
    group = PairingGroup('MNT224')
    g = group.random(G1)
    sk = group.random(ZR)
    h = sk * g

    return ((g, h), sk)

# Add randomness to a point
def rando(pk, c, r):
    group = PairingGroup('MNT224')
    return (c[0] + r * pk[1], c[1] + r * pk[0])

# ElGamal encryption with randomness r
def rspeq_enc(pk, m, r):
    group = PairingGroup('MNT224')
    return (r * pk[1] + m, r * pk[0])

# First move of the protocol
def rspeq_flow_1(pk0, pk1, c0, c1):
    group = PairingGroup('MNT224')
    r_1 = group.random(ZR)
    r_2 = group.random(ZR)
    rm = group.random(G1)
    return (rando(pk0, (c0[0] + rm, c0[1]), r_1), rando(pk1, (c1[0] + rm, c1[1]), r_2), rm, r_1, r_2)

# Second move of the protocol
def rspeq_flow_2():
    return bool(random.getrandbits(1))

# Third move of the protocol
def rspeq_flow_3(b, r0, r_0, r1, r_1):
    if b:
        return (r_0, r_1)
    else:
        return (r0 + r_0, r1 + r_1)

# Fourth move of the protocol
def rspeq_flow_4(b, pk0, pk1, c0, c_0, c1, c_1, rx, ry, rm):
    group = PairingGroup('MNT224')
    c00 = rando(pk0, (c0[0] + rm, c0[1]), rx)
    c11 = rando(pk1, (c1[0] + rm, c1[1]), ry)
    return c_0 == c00 and c_1 == c11
    
# Test functions
def rspeq_key_init_test(should_succeed):
    group = PairingGroup('MNT224')
    # Generate a key pair
    (g, h), sk = crs_gen()

    if should_succeed:
        return h == sk * g
    else:
        return h == g

def do_fast_test(should_succeed):
    group = PairingGroup('MNT224')
    # Generate a key pair
    pk0, _ = crs_gen()
    pk1, _ = crs_gen()
    m0 = group.random(ZR) * pk0[0]
    m1 = group.random(ZR) * pk0[1] if should_succeed else m0

    r0 = group.random(ZR)
    r1 = group.random(ZR)

    c0 = rspeq_enc(pk0, m0, r0)
    c1 = rspeq_enc(pk1, m1, r1)

    bo = True
    i = 0
    while i < 128 and bo:
        c_0, c_1, rm, r_0, r_1 = rspeq_flow_1(pk0, pk1, c0, c1)
        b = rspeq_flow_2()
        rx, ry = rspeq_flow_3(b, r0, r_0, r1, r_1)
        bo = rspeq_flow_4(b, pk0, pk1, c0, c_0, c1, c_1, rx, ry, rm)

        i += 1

    return bo

# Run the tests
init_test_result = rspeq_key_init_test(True)
fast_test_result = do_fast_test(True)

# Print the test results
print("Initialization Test:", init_test_result)
print("Fast Test:", fast_test_result)
