from lib.RSA_controller import RSA_controller
from lib.Oracle import Oracle
from implementation.BleichenBacherAttack import *


def print_starting_msg():
    print()
    print(" // =========================================== //")
    print("    Starting the bleichenbacher Oracle attack")
    print(" // =========================================== //")
    print()


if __name__ == "__main__":
    RSA_controller = RSA_controller(1024)
    msg = "This is a secret messsage i don't want to leak"
    # print(f"We're trying to hide the message: {msg}")
    cipher = RSA_controller.encrypt(msg)
    # print(f"I've encrypted the message to: {cipher}")
    # ori_msg = rsa.decrypt(cipher)
    # print(f"I've decrypted the message to: {ori_msg}")

    print_starting_msg()
    oracle = Oracle(RSA_controller)

    attackModule = BleichenBacherAttack(cipher, oracle, RSA_controller)
    attackModule.run()

    # print(f"PKCS conforming: {oracle.get_conforming_status(cipher)} ")
