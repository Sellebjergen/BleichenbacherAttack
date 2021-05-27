import rsa


class RSA_controller3:
    def __init__(self, amount_of_bits):
        self.amount_of_bits = amount_of_bits
        self.public_key, self.private_key = rsa.newkeys(amount_of_bits)

    def encrypt(self, msg):
        msg = str.encode(msg)
        encrypted_text = rsa.pkcs1.encrypt(msg, self.public_key)
        return encrypted_text

    def decrypt(self, encrypted_text):
        decrypted_text = rsa.pkcs1.decrypt(encrypted_text, self.private_key)
        return decrypted_text

    def get_public_key(self):
        return self.public_key

    def get_private_key(self):
        return self.private_key

    def get_amount_of_bits(self):
        return self.amount_of_bits
