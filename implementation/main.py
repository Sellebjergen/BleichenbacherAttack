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


def phase2c(c_0, s_i, interval):
    print("starting phase 2c")
    a, b = interval
    print(f"value of a: {a}")
    print(f"value of b: {b}")
    r_i = ceil(2 * (b * s_i - 2 * B), rsa_n)
    while True:
        lower_bound = ceil(2*B + r_i * rsa_n, b)
        higher_bound = ceil(3*B + r_i * rsa_n, a)
        if lower_bound > higher_bound:
            print(f"difference: {higher_bound - lower_bound}")
            exit(1)
        for s in range(lower_bound, higher_bound):
            math = c_0 * pow(s, rsa_e, rsa_n) % rsa_n
            math_bytes = long_to_bytes(math)
            if oracle.get_conforming_status(math_bytes):
                print("found a suitable values of r_i and s_i")
                return s
        r_i += 1


def phase3(s, M):
    print(f"there are {len(M)} intervals here in phase 3.")
    print("starting phase 3")
    new_M = []
    for a, b in M:
        lower_r = ceil(a * s - 3 * B + 1, rsa_n)
        higher_r = ceil(b * s - 2 * B, rsa_n)
        print("Differences in r higher and lower:")
        print(higher_r - lower_r)
        for r in range(lower_r, higher_r):
            lower_bound = max(a, ceil(2 * B + r * rsa_n, s))
            higher_bound = min(b, floor(3 * B - 1 + r * rsa_n, s))
            temp_interval = Interval(lower_bound, higher_bound)
            new_M.append(temp_interval)
    print(f"we've defined some new intervals there are now: {len(new_M)}")
    return new_M


def bleichenbacher(cipher_bytes):
    global s_i
    print("starting attack.")
    cipher_integer = bytes_to_long(cipher_bytes)
    M = [Interval(2 * B, 3 * B + 1)]
    i = 1

    # Step 1.   Blinding phase.
    # Is not necessary for now, as we know it's an encrypted message we're getting.

    # print("step 1 finished.")

    while True:
        # Doing step 2
        if i == 1:
            s_i = phase2a(cipher_integer)
        elif i > 1 and len(M) >= 2:
            s_i = phase2b(cipher_integer, s_i + 1)
        elif len(M) == 1:
            s_i = phase2c(cipher_integer, s_i, M[0])

        # Doing step 3
        M = phase3(s_i, M)

        # Doing step 4
        if len(M) == 1 and M[0].lower_bound == M[0].upper_bound:
            result = M[0].lower_bound % rsa_n
            return long_to_bytes(result)
        i += 1
        print("Doing another iteration of step 2.")


if __name__ == "__main__":
    # Doing some setup.
    msg = "another secret message"
    msg_encrypted_bytes = rsa.encrypt(msg)

    # Running the actual attack.
    print(bleichenbacher(msg_encrypted_bytes))
