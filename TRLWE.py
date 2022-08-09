import os
from pydoc import plain
import sys
import random
import numpy as np

class TRLWE():
    def __init__(self, plain_text, mu, n, sigma, k):
        self.plain_text = np.array(plain_text)
        self.mu = mu
        self.n = n
        self.k = k
        self.sigma = sigma
        
    def exec(self):
        converted_plain_text = self.convert_poly(self.plain_text, self.n)
        self.secret_key = self.generate_secret_key(self.n, self.k)
        self.cipher_vector = self.encrypt_calc(converted_plain_text, self.secret_key, self.n, self.sigma, self.k, self.mu)
        self.decrypt_text = self.decrypt_calc(self.cipher_vector, self.secret_key, self.k, self.n)

    def generate_public_key(self, n, k):
        random_from_os = random.SystemRandom()
        return np.array([[self.float_to_torus32(random_from_os.random()) for i in range(n)] for j in range(k)])

    def generate_secret_key(self, n, k):
        random_from_os = random.SystemRandom()
        return np.array([[1 if random_from_os.randint(0,1) >= 0.5 else 0 for i in range(n)] for j in range(k)])

    def generate_error(self,sigma):
        #モジューラ正規分布
        random_from_os = random.SystemRandom()
        random_normal = random_from_os.normalvariate(0, sigma)
        return np.array([self.float_to_torus32(random_normal)])

    def encrypt_calc(self, plain_text, secret_key, n, sigma, k, mu):
        cipher_vector = np.empty((k, n-1))

        public_key = self.generate_public_key(n, k)
        error = self.generate_error(sigma)
        public_secret_polymul = np.empty((n))
        for i in range(k):
            public_secret_polymul += self.polymul(n, public_key[i], secret_key[i])             

        cipher_text = public_secret_polymul + self.float_to_torus32(mu) * (2 * plain_text - 1) + error
        cipher_vector = np.vstack((public_key, cipher_text))
        return cipher_vector

    def decrypt_calc(self, cipher_vector, secret_key, k, n):
        decrypted_text = np.empty((n))

        public_secret_polymul = np.empty((n))
        for i in range(k):
            
            public_secret_polymul += self.polymul(n, cipher_vector[i], secret_key[i])         
        
        decrypted_text = (1 + np.sign(np.int32(cipher_vector[-1] - public_secret_polymul))) / 2

        return np.uint32(decrypted_text)

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
    
    def polymul(self, n, a, b):
        res = np.zeros(n, dtype=np.int64)
        for i in range(n):
            for j in range(n):
                #法はX^n+1だからmodを取ると、i(>=n)次元以上の次元の項は消えて、係数はi-n次元の係数から引く。
                if i + j < n: #次元がnよりも小さい時
                    res[i + j] += a[i] * b[j] #各次数の係数を順に足していく。
                else: #次元がnよりも大きい時
                    res[i + j - n] -= a[i] * b[j] #次元がn以上の時はk-n次元の係数に係数を引く。
        return res

    def convert_poly(self, plain_text, n): #与えられた多項式のX^n-1の剰余を取る & 次元が足りないときに0で補完する。
        res = np.zeros(n, dtype = np.int64)
        for i in range (n):
            if i < len(plain_text):
                res[i] += plain_text[i]
            else:
                if i > len(plain_text):
                    res[i] += 0
                else:
                    res[i-n] -= plain_text[i-len(plain_text)]
        return res

def main():
    mu = 2 ** -3
    n = 512
    sigma = 0.0000000342338787018369
    k = 2
    plain_text = [0,1,1,0,1,0,1]
    
    tlwe = TRLWE(plain_text, mu, n, sigma, k)
    tlwe.exec()
    #print(f"secret key:\n{tlwe.secret_key}")
    #print(f"error:\n{tlwe.error}")
    print(f"plain text:\n{tlwe.plain_text}")
    print(f"decrypt text:\n{tlwe.decrypt_text[:7]}")
    


if __name__ == '__main__':
    main()