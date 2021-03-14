from lib.RSA_controller import RSA_controller
from lib.Oracle import Oracle
from lib.BleichenBacherAttack import *


if __name__ == "__main__":
    rsa = RSA_controller(1024)
    oracle = Oracle(rsa)
    msg = "This is a secret messsage i don't want to leak"
    print(f"We're trying to hide the message: {msg}")
    cipher = rsa.encrypt(msg)
    print(f"I've encrypted the message to: {cipher}")
    ori_msg = rsa.decrypt(cipher)
    print(f"I've decrypted the message to: {ori_msg}")

    print(" // =========================================== //")
    print("    Starting the bleichenbacher PKCS 1.5 attack")
    print(" // =========================================== //")

    attackModule = BleichenBacherAttack(rsa, oracle)
    attackModule.run()
    print(attackModule.M)

    print(f"PKCS conforming: {oracle.get_conforming_status(cipher)} ")
