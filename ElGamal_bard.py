from charm.toolbox.pairinggroup import PairingGroup


def crs_gen():
    """Generate a key pair."""
    group = PairingGroup('curve25519')
    g = group.random()
    sk = group.random()
    h = sk * g
    return (g, h), sk


def rando(pk, c, r):
    """Add randomness to a point."""
    return c + r * pk[1]


def rspeq_enc(pk, m, r):
    """Encrypt a message with randomness."""
    return r * pk[1] + m


def rspeq_flow_1(pk0, pk1, c0, c1):
    """First move in the RSPEQ protocol."""
    r1 = group.random()
    r2 = group.random()
    rm = group.random()
    return rando(pk0, (c0.0 + rm, c0.1), r1), rando(pk1, (c1.0 + rm, c1.1), r2), rm, r1, r2


def rspeq_flow_2():
    """Second move in the RSPEQ protocol."""
    return group.random()


def rspeq_flow_3(b, r0, r_0, r1, r_1):
    """Third move in the RSPEQ protocol."""
    if b:
        return r_0, r_1
    else:
        return r0 + r_0, r1 + r_1


def rspeq_flow_4(b, pk0, pk1, c0, c_0, c1, c_1, rx, ry, rm):
    """Fourth move in the RSPEQ protocol."""
    if b:
        c00 = rando(pk0, (c0.0 + rm, c0.1), rx)
        c11 = rando(pk1, (c1.0 + rm, c1.1), ry)
        return c_0 == c00 and c_1 == c11
    else:
        return c_0.0 - (rx * pk0[1]) == c_1.0 - (ry * pk1[1])


def main():
    """Test the RSPEQ protocol."""
    (pk0, sk0) = crs_gen()
    (pk1, sk1) = crs_gen()
    m0 = group.zero() * pk0[0]
    m1 = group.one() * pk0[1]

    success = True
    for i in range(128):
        if not do_fast_test(True):
            success = False
            break

    if success:
        print("Test passed")
    else:
        print("Test failed")


if __name__ == "__main__":
    main()
