from implementation.lib.Oracle import Oracle
from lib.RSA_controller import RSA_controller
from Crypto.Util.number import bytes_to_long, long_to_bytes
from collections import namedtuple

# setting some global variables.
rsa = RSA_controller(1024)
rsa_e = rsa.get_public_key().e
rsa_n = rsa.get_public_key().n
k = rsa.get_amount_of_bits() // 8
B = 2 ** (8 * (k - 2))
oracle = Oracle(rsa)
Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])


def ceil(a, b):
    return a // b + (a % b > 0)


def floor(a, b):
    return a // b


def blinding_phase(c):
    print("starting the blinding phase")
    s_0 = 1
    while True:
        c_0_math = c * pow(s_0, rsa_e, rsa_n) % rsa_n
        c_0_math_bytes = long_to_bytes(c_0_math)
        if oracle.get_conforming_status(c_0_math_bytes):
            return c_0_math
        s_0 += 1


def phase2a(c):
    print("starting phase 2a")
    s_1 = ceil(rsa_n, 3 * B)
    print(f"starting with the value of: {s_1}")
    while True:
        math = (c * pow(s_1, rsa_e, rsa_n)) % rsa_n
        math_bytes = long_to_bytes(math)
        if oracle.get_conforming_status(math_bytes):
            print("now the value of s_1 is")
            print(s_1)
            return s_1
        s_1 += 1


def phase2b(c, s_i):
    print("starting phase 2b")
    while True:
        math = (c * pow(s_i, rsa_e, rsa_n)) % rsa_n
        math_bytes = long_to_bytes(math)
        if oracle.get_conforming_status(math_bytes):
            print("now the value of s_1 is")
            print(s_i)
            return s_i
        s_i += 1


def phase2c(c_0, M):
    a, b = M[0]
    return 0, 0


def phase3(s, M):
    new_M = []
    for a, b in M:
        lower_r = (a * s - 3 * B + 1) // rsa_n
        higher_r = (b * s - 2 * B) // rsa_n
        print("Differences in r higher and lower:")
        print(higher_r - lower_r)
        for r in range(lower_r, higher_r):
            temp_interval = Interval(max(a, (2 * B + r * rsa_n) // s), min(b, (3 * B - 1 + r * rsa_n) // s))
            new_M.append(temp_interval)
    print(f"we've defined some new intervals there are now: {len(new_M)}")
    return new_M


def bleichenbacher(cipher_bytes):
    print("starting attack.")
    cipher_integer = bytes_to_long(cipher_bytes)
    M = [Interval(2 * B, 3 * B + 1)]
    i = 1

    # Step 1.   Blinding phase.
    # Is not necessary for now, as we know it's an encrypted message we're getting.

    print("step 1 finished.")


    # TODO: this should be in a forloop, with i as the increment.
    # step 2.a  First iteration
    s_i = -1
    if i == 1:
        s_i = phase2a(cipher_integer)
    elif i > 1 and len(M) >= 2:
        s_i = phase2b(cipher_integer, s_i + 1)
    elif len(M) == 1:
        a, b = M[0]
        r_i, s_i = phase2c()

    print("step 2 finished.")
    print("We're done")

    if s_i == -1:
        # TODO: raise some kind of exception.
        print("An error has happened. The value of s_1 is not set incorrect.")

    # step 3.   Narrowing set of solutions.
    M = phase3(s_i, M)

    # step 4.   Computing the solution.
    if len(M) == 1 and M[0].lower_bound == M[0].upper_bound:
        # TODO: still need to implement the values to return.
        result = M[0].lower_bound % rsa_n
        return result


if __name__ == "__main__":
    # Doing some setup.
    msg = "secret message"
    msg_encrypted_bytes = rsa.encrypt(msg)

    # Running the actual attack.
    bleichenbacher(msg_encrypted_bytes)
