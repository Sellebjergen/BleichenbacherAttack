from implementation.RSA_controller import RSA_controller
from implementation.Oracle import Oracle
from implementation.BleichenBacherAttack import *


def print_starting_msg():
    print()
    print(" // =========================================== //")
    print("     Starting the bleichenbacher Oracle attack    ")
    print(" // =========================================== //")
    print()


if __name__ == "__main__":
    RSA = RSA_controller(256)
    msg = "AES=1234512345"
    cipher = RSA.encrypt(msg)
    print_starting_msg()
    oracle = Oracle(RSA_controller)
    attackModule = BleichenBacherAttack(cipher, oracle, RSA)
    attackModule.run()
