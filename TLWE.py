import os
from pydoc import plain
import sys
import random
import numpy as np

class TLWE():
    def __init__(self, plain_text, mu, n, sigma):
        self.plain_text = plain_text
        self.mu = mu
        self.n = n
        self.sigma = sigma
        
    def exec(self):
        self.secret_key = self.generate_secret_key(self.n)
        self.cipher_vector = self.encrypt_calc(self.plain_text, self.secret_key)
        self.decrypt_text = self.decrypt_calc(self.cipher_vector, self.secret_key)
        
    def generate_public_key(self, n):
        random_from_os = random.SystemRandom()
        return [random_from_os.random() for i in range(n)]

    def generate_secret_key(self, n):
        random_from_os = random.SystemRandom()
        return [1 if random_from_os.randint(0,1) >= 0.5 else 0 for i in range(n)]

    def generate_error(self,sigma):
        #モジューラ正規分布
        random_from_os = random.SystemRandom()
        return random_from_os.normalvariate(0, sigma) % 1

    def encrypt_calc(self, plain_text, secret_key):
        cipher_vector = np.empty((len(plain_text), self.n + 1))
        for index in range(len(self.plain_text)):
            public_key = self.generate_public_key(self.n)
            error = self.generate_error(self.sigma)
            cipher_text = np.dot(public_key, secret_key) + self.mu * (2 * self.plain_text[index] - 1) + error
            cipher_vector[index] = np.append(public_key, cipher_text)
        return cipher_vector

    def decrypt_calc(self, cipher_vector, secret_key):
        decrypted_text = np.empty((len(self.plain_text)))
        for index in range(len(self.plain_text)):
            decrypted_text[index] = (1 + np.sign(cipher_vector[index][-1] - np.dot(cipher_vector[index][:-1], secret_key))) / 2
        return decrypted_text
    
    def float_to_torus32(self, d):
        return np.uint32((d % 1) * 2 ** 32)
        """
        R mod 1 の小数部分を32bitで表現したい。
        →整数部分を押し出して、表現すればよい
        1. ひとまず、modを取る
        →この段階では、ただのfloat型
        2. 型をuint32(符号なし32bit整数)に指定
        3. modを取った数に2の32乗をかける。
        →これで、整数部分に小数部分が押し出される。
        4. 加算、乗算したときも、整数部分は押し出されて関係なくなるからOK
        """
        
def main():
    mu = 2 ** -3
    n = 586
    sigma = 0.0000925119974676756
    plain_text = [0]
    
    tlwe = TLWE(plain_text, mu, n, sigma)
    tlwe.exec()
    #print(f"secret key:\n{tlwe.secret_key}")
    #print(f"error:\n{tlwe.error}")
    print(f"plain text:\n{tlwe.plain_text}")
    print(f"decrypt text:\n{tlwe.decrypt_text}")
    


if __name__ == '__main__':
    main()