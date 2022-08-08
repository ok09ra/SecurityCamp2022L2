import os
import sys
import random
import numpy as np

class TLWE():
    #平文がTorusな場合を実装
    def __init__(self, plain_text, n, modula_mu, modula_sigma):
        self.plain_text = plain_text
        self.length = len(self.plain_text)
        self.modula_mu = modula_mu
        self.modula_sigma = modula_sigma
        self.n = n

    def encrypt_basic(self):
        self.generate_public_key()
        self.generate_secret_key()
        self.generate_error(self.modula_mu, self.modula_sigma)
        self.encrypt_calc()
        return np.append(self.public_key, self.cipher_text)

    def generate_public_key(self):
        random_from_os = random.SystemRandom()
        self.public_key = [np.uint32(random_from_os.random()) for i in range(self.n)]

    def generate_secret_key(self):
        random_from_os = random.SystemRandom()
        self.secret_key = [np.uint32(random_from_os.random()) for i in range()randint(0,1) for i in range(self.n)]

    def generate_error(self, mu, sigma):
        #モジューラ正規分布
        random_from_os = random.SystemRandom()
        self.error = np.mod(np.uint32(random_from_os.normalvariate(mu, sigma)), 1)

    def encrypt_calc(self):
        self.cipher_text = np.uint32(np.dot(self.public_key, self.secret_key) + self.plain_text + self.error)


    def decrypt_calc(self, encrypted_text:
        return np.uint32(1 + np.sign(np.uint32()))

    def bootstrap(self):

    def decrypt(self):


def main():
    tlwe = TLWE("asdfghjkl;", 0, 0.1)
    tlwe.exec()
    print(tlwe.public_key)
    print(tlwe.secret_key)
    print(tlwe.error)
    


if __name__ == '__main__':
    main()