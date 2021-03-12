from lib.RSA_controller import RSA_controller
from lib.Oracle import Oracle


if __name__ == "__main__":
    rsa = RSA_controller(1024)
    oracle = Oracle(rsa)
    msg = "This is a secret messsage i don't want to leak"
    print(f"We're trying to hide the message: {msg}")
    cipher = rsa.encrypt(msg)
    print(f"I've encrypted the message to: {cipher}")
    ori_msg = rsa.decrypt(cipher)
    print(f"I've decrypted the message to: {ori_msg}")

    print(f"PKCS conforming: {oracle.get_conforming_status(cipher)} ")
