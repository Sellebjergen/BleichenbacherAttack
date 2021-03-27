from implementation.lib.Oracle import Oracle
from lib.RSA_controller import RSA_controller
from Crypto.Util.number import bytes_to_long, long_to_bytes
from collections import namedtuple

# setting some global variables.
rsa = RSA_controller(1024)
rsa_e = rsa.get_public_key().e
rsa_n = rsa.get_public_key().n
B = 2 ** (8 * (256 - 2))
oracle = Oracle(rsa)
Interval = namedtuple("Interval", ["lower_bound", "upper_bound"])


def blinding_phase(c):
    s_0 = 1
    while True:
        c_0_math = c * pow(s_0, rsa_e, rsa_n) % rsa_n
        c_0_math_bytes = long_to_bytes(c_0_math)
        if oracle.get_conforming_status(c_0_math_bytes):
            return c_0_math
        s_0 += 1


def phase2a(c_0):
    s_1 = (rsa_n // 3 * B) + 1
    print(f"starting with the value of: {s_1}")
    while True:
        math = c_0 * pow(s_1, rsa_e, rsa_n) % rsa_n
        math_bytes = long_to_bytes(math)
        if oracle.get_conforming_status(math_bytes):
            return s_1
        s_1 += 1


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
    return new_M


def bleichenbacher(cipher_bytes):
    print("starting attack.")
    cipher_integer = bytes_to_long(cipher_bytes)
    M = [Interval(2 * B, 3 * B + 1)]
    i = 1

    # Step 1.   Blinding phase.
    c_0 = blinding_phase(cipher_integer)

    print("step 1 finished.")

    # step 2.a  First iteration
    s_1 = -1
    if i == 1:
        s_1 = phase2a(c_0)

    print("step 2 finished.")
    print("We're done")

    if s_1 == -1:
        print("An error has happened. The value of s_1 is not set incorrect.")

    # step 3.   Narrowing set of solutions.
    M = phase3(s_1, M)

    # step 4.   Computing the solution.
    if len(M) == 1:
        print("we're done.")


if __name__ == "__main__":
    # Doing some setup.
    msg = "secret message"
    msg_encrypted_bytes = rsa.encrypt(msg)

    # Running the actual attack.
    bleichenbacher(msg_encrypted_bytes)
