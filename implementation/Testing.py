import unittest

from lib.Oracle import Oracle
from lib.RSA_controller import RSA_controller


class MyTestCase(unittest.TestCase):
    def test_encrypt_decrypt(self):
        rsa = RSA_controller(1024)
        oracle = Oracle(rsa)
        msg = "This is a secret messsage i don't want to leak"
        cipher = rsa.encrypt(msg)
        ori_msg = rsa.decrypt(cipher)
        self.assertEqual(bytes(msg, "utf-8"), ori_msg)

    def test_Oracle_return_true_PKCS_conforming_status(self):
        rsa = RSA_controller(1024)
        oracle = Oracle(rsa)
        msg = "This is a secret messsage i don't want to leak"
        cipher = rsa.encrypt(msg)
        self.assertEqual(True, oracle.get_conforming_status(cipher))


if __name__ == '__main__':
    unittest.main()
