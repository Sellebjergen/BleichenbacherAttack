from implementation.lib.BleichenBacherAttack import BleichenBacherAttack
from implementation.lib.Oracle import Oracle
from implementation.lib.RSA_controller import RSA_controller

if __name__ == '__main__':
    # Setting up the RSA and oracle to use.
    rsa = RSA_controller(2048)
    oracle = Oracle(rsa)

    # encrypting the message.
    msg = "secret message"
    msg_encrypted_bytes = rsa.encrypt(msg)

    # performing the attack given the rsa and oracle.
    result = BleichenBacherAttack(rsa, oracle).run(msg_encrypted_bytes)
    print(str(result))
