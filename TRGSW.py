import os
from pydoc import plain
import sys
import random
import numpy as np


class TRGSW():
    def __init__(self, mu_vec, Bgbit, l, mu, n, sigma, k):
        self.cipher_trlwe_length = k+1
        self.mu_vec = np.array(mu_vec)
        self.Bgbit = Bgbit
        self.Bg = 2 ** Bgbit
        self.l = l

        self.mu = mu
        self.n = n
        self.sigma = sigma
        self.k = k
        
    def exec(self):
        zero_trlwe_vector = []
        for i in range(self.l * (self.k+1)):
            zero_trlwe = TRLWE([0], self.mu, self.n, self.sigma, self.k)
            zero_trlwe.exec_torus()
            zero_trlwe_vector.append(zero_trlwe.cipher_vector)
        
        zero_trlwe_vector = np.array(zero_trlwe_vector)
        print(f"zero_telwe_vector:\n{zero_trlwe_vector}")
        mu_matrix = self.generate_mu_matrix(self.mu_vec, self.Bg, self.cipher_trlwe_length, self.l)
        self.cipher_vector = self.trgsw(zero_trlwe_vector, mu_matrix)
    
    def generate_mu_matrix(self, mu_vec, Bg, cipher_trlwe_length, l):
        #print(f"mu:\n{mu_vec}")
        mu_vec_poly = self.convert_poly(mu_vec, self.n)
        #print(f"mu_vec_poly:\n{mu_vec_poly}")
        mu_matrix = np.zeros(( l * cipher_trlwe_length, cipher_trlwe_length,  mu_vec_poly.shape[0]))
        mu_Bg_array = np.array([self.float_to_torus32(mu_vec_poly / (Bg ** i)) for i in range(1,l+1)])
        for i in range(cipher_trlwe_length):
            mu_matrix[l * i: l * (i + 1),i,:] = mu_Bg_array
            
        #print(f"mu matrix:\n{np.uint32(mu_matrix)}")
        return np.uint32(mu_matrix)
    
    def trgsw(self, zero_trlwe, mu_matrix):
        return zero_trlwe + mu_matrix
    
    def convert_poly(self, plain_text, n): #与えられた多項式のX^n-1の剰余を取る & 次元が足りないときに0で補完する。
        res = np.zeros(n, dtype = np.int64)
        for i in range (n):
            if i < len(plain_text):
                res[i] += plain_text[i]
                
            else:
                if i >= len(plain_text):
                    res[i] += 0
                else:
                    res[i-n] -= plain_text[i-len(plain_text)]
        return res
    
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

        
class ExternalProduct():
    def __init__(self, cipher_trlwe, cipher_trgsw, mu, Bgbit, l):
        self.cipher_trlwe = cipher_trlwe
        self.cipher_trlwe_length = cipher_trlwe.shape[0]
        self.cipher_trgsw = cipher_trgsw
        self.mu = np.array(mu)
        self.Bgbit = Bgbit
        self.Bg = 2 ** Bgbit
        self.l = l
        
    def exec(self):
        self.decomposed_trlwe = self.decompose_trlwe(self.cipher_trlwe, self.Bgbit, self.l)
        self.encrypted_text = self.exec_calc(self.decomposed_trlwe, self.cipher_trgsw)
    
    def decomposition(self, a, l, Bgbit):
        round_offset = 1 << (32 - l * Bgbit -1)
        decomposed_a_slip = np.empty((l , len(a)))
        decomposed_a = np.empty((l , len(a)))
        for i in range(l):
            for j in range(len(a)):
                decomposed_a_slip[i][j] = (a[j] + round_offset) >> (32 - Bgbit * i) & (2 ** Bgbit - 1)
        for i in range(l):
            for j in range(len(a)):
                if decomposed_a_slip[i][j] >= 2 ** (Bgbit - 1):
                    decomposed_a[i][j] = decomposed_a_slip[i][j] - 2 ** Bgbit
                    decomposed_a_slip[i-1][j] += 1
                else:
                    decomposed_a[i][j] = decomposed_a_slip[i][j]

        #print(f"decomposed_a {decomposed_a.shape}\n{decomposed_a}")
        
        #print(f"decomposed_a reshape {decomposed_a.reshape(1,l,len(a)).shape}\n{decomposed_a.reshape(1,l,len(a))}")
        return decomposed_a.reshape(1,l,len(a))

    def decompose_trlwe(self, cipher_trlwe, Bgbit, l):
        decomposed_vector = np.empty((1, 0, cipher_trlwe.shape[1]))
        for cipher_torus_vector in cipher_trlwe:
            decomposed_vector = np.hstack([decomposed_vector, self.decomposition(cipher_torus_vector, l, Bgbit)])

        return np.array(decomposed_vector)
    
    def exec_calc(self, decomposed_trlwe, trgsw):
        trgsw_matrix = []
        for j in range(trgsw.shape[1]):
            trgsw_vector = np.empty((decomposed_trlwe.shape[2]))
            for i in range(decomposed_trlwe.shape[1]):
                trgsw_vector += self.polymul(decomposed_trlwe.shape[2], decomposed_trlwe[0, i, :], trgsw[i, j, :])

            trgsw_matrix.append(trgsw_vector)
        print(f"trgsw \n{np.uint32(np.array(trgsw_matrix))}")
        return np.uint32(np.array(trgsw_matrix))

    def polymul(self, n, a, b):
        res = np.zeros(n, dtype=np.int64)
        for i in range(n):
            for j in range(n):
                #法はX^n+1だからmodを取ると、i(>=n)次元以上の次元の項は消えて、係数はi-n次元の係数から引く。
                if i + j < n: #次元がnよりも小さい時
                    res[i + j] += np.uint32(a[i]) * np.uint32(b[j]) #各次数の係数を順に足していく。
                else: #次元がnよりも大きい時
                    res[i + j - n] -= np.uint32(a[i]) * np.uint32(b[j]) #次元がn以上の時はk-n次元の係数に係数を引く。
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



class CMUX():
    def __init__(self, cipher_trgsw, mu, k, sigma, n, Bgbit, l):
        self.cipher_trgsw = cipher_trgsw
        self.mu = mu
        self.k = k
        self.sigma = sigma
        self.n = n
        self.Bgbit = Bgbit
        self.l = l
        
    def exec(self):
        trlwe_zero = TRLWE([0], self.mu, self.n, self.sigma, self.k)
        trlwe_one = TRLWE([1], self.mu, self.n, self.sigma, self.k)
        trlwe_zero.exec()
        trlwe_one.exec()
        
        external_product = ExternalProduct(np.uint32(trlwe_one.cipher_vector - trlwe_zero.cipher_vector), self.cipher_trgsw, self.mu, self.Bgbit, self.l)
        external_product.exec()
        
        self.result = external_product.encrypted_text + trlwe_zero.cipher_vector
        

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

    def exec_torus(self):
        converted_plain_text = self.convert_poly(self.plain_text, self.n)
        self.secret_key = self.generate_secret_key(self.n, self.k)
        self.cipher_vector = self.encrypt_calc_torus(converted_plain_text, self.secret_key, self.n, self.sigma, self.k, self.mu)
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

        cipher_text = self.float_to_torus32(public_secret_polymul) + self.float_to_torus32(mu) * (2 * plain_text - 1) + error
        cipher_vector = np.vstack((public_key, cipher_text))

        return cipher_vector

    def encrypt_calc_torus(self, plain_text, secret_key, n, sigma, k, mu):
        cipher_vector = np.empty((k, n-1))

        public_key = self.generate_public_key(n, k)
        error = self.generate_error(sigma)
        public_secret_polymul = np.empty((n))
        
        plain_text_torus = []
        for i in plain_text:
            plain_text_torus.append(self.float_to_torus32(i))
        plain_text_torus = np.array(plain_text_torus)
        
        for i in range(k):
            public_secret_polymul += self.polymul(n, public_key[i], secret_key[i])             

        cipher_text = self.float_to_torus32(public_secret_polymul) + plain_text_torus + error
        cipher_vector = np.vstack((public_key, cipher_text))

        return cipher_vector
    
    def decrypt_calc(self, cipher_vector, secret_key, k, n):
        decrypted_text = np.empty((n))

        public_secret_polymul = np.empty((n))
        for i in range(k):
            public_secret_polymul += self.polymul(n, cipher_vector[i], secret_key[i])         
        
        decrypted_text = (1 + np.sign(np.int32(cipher_vector[-1] - self.float_to_torus32(public_secret_polymul)))) / 2


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
                    res[i + j] += np.uint32(a[i]) * np.uint32(b[j]) #各次数の係数を順に足していく。
                else: #次元がnよりも大きい時
                    res[i + j - n] -= np.uint32(a[i]) * np.uint32(b[j]) #次元がn以上の時はk-n次元の係数に係数を引く。
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
    mu = 2 ** -3 #TRLWE用のmu
    n = 512
    sigma = 0.0000000342338787018369
    k = 2
    plain_text = [1]

    mu_vec = [1] #External Productのかけられるベクトルmu
    Bgbit = 8
    l = 2
    
    input_vec = [1]

    trlwe = TRLWE(plain_text, mu, n, sigma, k)
    trlwe.exec()
    
    trgsw = TRGSW(mu_vec, Bgbit,l, mu, n, sigma, k)
    trgsw.exec()

    external_product = ExternalProduct(trlwe.cipher_vector, trgsw.cipher_vector , mu, Bgbit, l)
    external_product.exec()

    decrypted_text = trlwe.decrypt_calc(external_product.encrypted_text, trlwe.secret_key, trlwe.k, trlwe.n)
    
    #print(f"secret key:\n{tlwe.secret_key}")
    #print(f"error:\n{tlwe.error}")
    print(f"plain text:\n{trlwe.plain_text}")
    print(f"mu: \n{mu_vec}")
    print(f"decrypt text:\n{decrypted_text[:len(plain_text)]}")
    
    trgsw_for_cmux = TRGSW(input_vec, Bgbit,l, mu, n, sigma, k)
    trgsw_for_cmux.exec()
    
    cmux = CMUX(trgsw_for_cmux.cipher_vector, mu, k, sigma, n, Bgbit, l)
    cmux.exec()
    print(f"CMUX result:\n{cmux.result}")

    


if __name__ == '__main__':
    for i in range(10):
        main()