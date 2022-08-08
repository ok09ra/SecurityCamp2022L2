import os
from pydoc import plain
import sys
import random
import numpy as np

#平文はバイナリでやる
class TLWE():
    def __init__(self, plain_text, mu, n, sigma):
        self.plain_text = plain_text
        self.mu = mu
        self.n = n
        self.sigma = sigma
        
    def exec(self):
        self.secret_key = self.generate_secret_key(self.n)
        self.error = self.generate_error(self.n, self.mu, self.sigma)
        self.cipher_vector = self.encrypt_calc(self.plain_text, self.secret_key, self.error)
        self.decrypt_text = self.decrypt_calc(self.cipher_vector, self.secret_key)
        
    def generate_public_key(self, n):
        random_from_os = random.SystemRandom()
        return [np.float32(random_from_os.random()) for i in range(n)]

    def generate_secret_key(self, n):
        random_from_os = random.SystemRandom()
        return [np.uint32(1) if random_from_os.randint(0,1) > 0.5 else np.uint32(0) for i in range(n)]

    def generate_error(self, n, mu, sigma):
        #モジューラ正規分布
        random_from_os = random.SystemRandom()
        return [np.mod(np.float32(random_from_os.normalvariate(mu, sigma)), 1) for i in range(n)]

    def encrypt_calc(self, plain_text, secret_key, error):
        cipher_vector = np.empty((len(plain_text), self.n + 1))
        for index in range(len(self.plain_text)):
            public_key = self.generate_public_key(self.n)
            cipher_text = np.float32(np.dot(public_key, secret_key) + self.mu * (2 * self.plain_text[index] - 1) + error[index])
            cipher_vector[index] = np.append(public_key, cipher_text)
        return cipher_vector

    def decrypt_calc(self, cipher_vector, secret_key):
        decrypted_text = np.empty((len(self.plain_text)))
        for index in range(len(self.plain_text)):
            decrypted_text[index] = np.float32(1 + np.sign(cipher_vector[index][-1] - np.dot(cipher_vector[index][:-1], secret_key))) / 2
        return decrypted_text
    
def main():
    mu = 2 ** -3
    n = 635
    sigma = 2 ** -19
    plain_text = [0]
    
    tlwe = TLWE(plain_text, mu, n, sigma)
    tlwe.exec()
    #print(f"secret key:\n{tlwe.secret_key}")
    #print(f"error:\n{tlwe.error}")
    print(f"plain text:\n{tlwe.plain_text}")
    print(f"decrypt text:\n{tlwe.decrypt_text}")
    


if __name__ == '__main__':
    main()