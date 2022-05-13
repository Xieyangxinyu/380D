import hashlib
import binascii
import operator
import math
import random
import numpy as np
import time

import matplotlib.pyplot as plt
import seaborn as sns

import sys
from sys import argv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def integer_byte_size(n):
    '''Returns the number of bytes necessary to store the integer n.'''
    quanta, mod = divmod(integer_bit_size(n), 8)
    if mod or n == 0:
        quanta += 1
    return quanta

def integer_bit_size(n):
    '''Returns the number of bits necessary to store the integer n.'''
    if n == 0:
        return 1
    s = 0
    while n:
        s += 1
        n >>= 1
    return s

def integer_ceil(a, b):
    '''Return the ceil integer of a div b.'''
    quanta, mod = divmod(a, b)
    if mod:
        quanta += 1
    return quanta

class RsaPublicKey(object):
    __slots__ = ('n', 'e', 'bit_size', 'byte_size')

    def __init__(self, n, e):
        self.n = n
        self.e = e
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    def __repr__(self):
        return '<RsaPublicKey n: %d e: %d bit_size: %d>' % (self.n, self.e, self.bit_size)

    def rsavp1(self, s):
        if not (0 <= s <= self.n-1):
            raise Exception("s not within 0 and n - 1")
        return self.rsaep(s)

    def rsaep(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return pow(m, self.e, self.n)

class RsaPrivateKey(object):
    __slots__ = ('n', 'd', 'bit_size', 'byte_size')

    def __init__(self, n, d):
        self.n = n
        self.d = d
        self.bit_size = integer_bit_size(n)
        self.byte_size = integer_byte_size(n)

    def __repr__(self):
        return '<RsaPrivateKey n: %d d: %d bit_size: %d>' % (self.n, self.d, self.bit_size)

    def rsadp(self, c):
        if not (0 <= c <= self.n-1):
            raise Exception("c not within 0 and n - 1")
        return pow(c, self.d, self.n)

    def rsasp1(self, m):
        if not (0 <= m <= self.n-1):
            raise Exception("m not within 0 and n - 1")
        return self.rsadp(m)

def i2osp(x, x_len):
    '''
    Converts the integer x to its big-endian representation of length
    x_len.
    '''
    # if x > 256**x_len:
    #     raise ValueError("integer too large")
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return b'\x00' * int(x_len-len(x)) + x

def os2ip(x):
    '''
    Converts the byte string x representing an integer reprented using the
    big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return int(h, 16)

def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    '''
    Mask Generation Function v1 from the PKCS#1 v2.0 standard.
    mgs_seed - the seed, a byte string
    mask_len - the length of the mask to generate
    hash_class - the digest algorithm to use, default is SHA1
    Return value: a pseudo-random mask, as a byte string
    '''
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = b''
    for i in range(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        C_str = str(C, 'utf-8')
        concat_seed = (mgf_seed + C_str).encode('utf-8')
        T = T + hash_class(concat_seed).digest()
    return T[:mask_len]

def VRF_prove(private_key, alpha, k):
    # k is the length of pi
    EM = mgf1(alpha, k-1)
    m = os2ip(EM)
    s = private_key.rsasp1(m)
    pi = i2osp(s, k)
    return pi

def VRF_proof2hash(pi, hash=hashlib.sha1):
    beta = hash(pi).digest()
    return beta

def VRF_verifying(public_key, alpha, pi, k):
    s = os2ip(pi)
    m = public_key.rsavp1(s)
    EM = i2osp(m, k-1)
    EM_ = mgf1(alpha, k-1)
    #print("Evaluation:", os2ip(EM_))

    if EM == EM_:
        return "VALID"
    else:
        return "INVALID"


if __name__ == "__main__":
    if len(argv) < 2:
        print ("USAGE: python RSA_VRF.py [alpha]")
        exit(1)

    time_before_keygen = time.perf_counter()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size= 1024,
        backend=default_backend())

    private_numbers = private_key.private_numbers()
    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    time_after_keygen = time.perf_counter()
    print("Time for RSA key generation:", (time_after_keygen - time_before_keygen)*1000, " miliseconds")


    total_keygen_time = 0
    total_proof_time = 0
    total_verify_time = 0

    initial_keygen_time = (time_after_keygen - time_before_keygen)*1000


    n = public_numbers.n
    e = public_numbers.e
    d = private_numbers.d
    k = 30

    party_size = 30
    epoch_number = 1000



    initial_distr = np.random.normal(5, 1, party_size)

    stakeholders = list(range(1, party_size+1))

    print("stakeholders:", stakeholders)

    print("initial_distr: ",initial_distr)

    total_stake = 0

    for i in range(len(initial_distr)):
        total_stake += initial_distr[i]

    print("Current total stake:", total_stake)

    plt.bar(stakeholders, initial_distr)
    plt.xticks(stakeholders, stakeholders)
    plt.title('Initial Distribution of Stakes')
    plt.xlabel('Participant')
    plt.ylabel('Stakes')

    plt.savefig("initial.jpg")

    stake_range = list(range(1, 9))

    plt.clf()
    plt.plot(stakeholders, initial_distr, 'bo')
    
    plt.xticks(stakeholders, stakeholders)
    plt.yticks(stake_range, stake_range)
    plt.xlabel('Participant')
    plt.ylabel('Stakes')
    plt.savefig("initial_plot.jpg")
   
    alpha = " ".join(argv[1:])

    final_distr = initial_distr

    
    for epoch in range(epoch_number):
      
        print("Epoch number:", epoch)


        time_before_keygen = time.perf_counter()
        public_key = RsaPublicKey(n, e)
        private_key = RsaPrivateKey(n, d)

        time_after_keygen = time.perf_counter()
        total_keygen_time += (time_after_keygen - time_before_keygen)*1000
        
        #print("Time for key generation:", (time_after_keygen - time_before_keygen)*1000, " miliseconds")

        current_chain = " "
        for stake in final_distr:
            current_chain += str(stake)

        time_before_proof = time.perf_counter()

        time_stamp = str(epoch)

        input_val = alpha+current_chain+time_stamp

        pi = VRF_prove(private_key, input_val, k)

        time_after_proof = time.perf_counter()
        total_proof_time += (time_after_proof - time_before_proof)*1000

        print("Time for proof generation:", (time_after_proof - time_before_proof)*1000, " miliseconds")


        beta = VRF_proof2hash(pi)

        beta_val = os2ip(beta)
        #print("Evaluation:", beta_val)
        #print("Random str Length:", len(str(beta_val)))

        time_before_verify = time.perf_counter()

        print(VRF_verifying(public_key, input_val, pi, k))

        time_after_verify = time.perf_counter()

        total_verify_time += (time_after_verify - time_before_verify)*1000
        print("Time for verification:", (time_after_verify - time_before_verify)*1000, " miliseconds")




        beacon = int(str(beta_val)[0:30])

        #print("Beacon for leader selection:", beacon)

        random.seed(beacon)

        leaders = random.choices(stakeholders, weights= final_distr, k = 3)

        print("Leader for epoch ", epoch, ":", leaders)

        for leader in leaders:
            final_distr[leader-1] += 0.01


        print("Stake distribution after epoch ", epoch, ": ", final_distr)


        

        #print(current_chain)

        alpha = str(beta_val)[30:]
        #print("Beacon for next round:", alpha)



    plt.plot(stakeholders, final_distr, 'ro')
    plt.xticks(stakeholders, stakeholders)
    plt.yticks(stake_range, stake_range)
    plt.xlabel('Participant')
    plt.ylabel('Stakes')
    plt.savefig("compare.jpg")


    plt.clf()
    

    plt.bar(stakeholders, final_distr, color = 'orange')
    plt.xticks(stakeholders, stakeholders)
    plt.title('Final Distribution of Stakes')
    plt.xlabel('Participant')
    plt.ylabel('Stakes')

    plt.savefig("output.jpg")
    


    #print("Initial_distr: ",initial_distr)
    print("Final stake distribution: ", final_distr)

    print("Avg keygen time:", initial_keygen_time, " miliseconds")
    print("Avg proof time:", total_proof_time/epoch_number, " miliseconds")
    print("Avg verify time:", total_verify_time/epoch_number, " miliseconds")

    print("Current total stake:", total_stake)


    

    
