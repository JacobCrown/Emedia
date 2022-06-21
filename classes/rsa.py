from sys import byteorder
import sympy
import random
import time
import math

class RSA:
    def __init__(self, length, nonce=None):
        print("Checking key length")
        self.byte_length = length // 8
        self.block_length = self.byte_length - 1
        assert length / 8 == self.byte_length, "RSA key must be mod 8"
        
        self.display_info = False
        self.last_block_length = 1
        
        self.length = length
        self.publicKey = 0
        self.privateKey = 0

        self.nonce = nonce if nonce != None else self.generate_nonce()
        
    def __str__(self):
        return f"byte_length - {self.byte_length} \npublicKey - {self.publicKey != 0} \nprivateKey - {self.private != 0}"
        
        
    def generate_keys(self):
        print(f"Key length valid \nGenerating {self.length}bit key...")
        self.publicKey,self.privateKey = self.createKeys()
    
    def load_private_key(self, d,n):
        self.privateKey = (d,n)
     
    def load_public_key(self, d,n):
        self.publicKey = (d,n)

    def set_last_block_length(self,new_value):
        self.last_block_length = new_value
        
    def show_info(self,info):
        if self.display_info == False:
            return
        print(info)
        time.sleep(0.1)
        
    def crypto(self,block):
        a = self.publicKey[0]
        b = self.publicKey[1]
        return pow(block,self.publicKey[0],self.publicKey[1])
    
    def decrypto(self,block):
        return pow(block,self.privateKey[0],self.privateKey[1])
        
    def createKeys(self):
        
        def gcd(a,b): # Greates Common Divisor
            while b != 0:
                a, b = b, a % b
            return a
            
        def isCoprime(num1,num2):
            return gcd(num1,num2) == 1
        
        def inverse(x,m):
            a, b, u = 0, m, 1
            while x > 0:
                q = b // x
                x, a, b, u = b%x, u, x, a - q * u
            if b == 1: return a % m
            print("error must be coprime")
        
        def Rabin_Miller(n):
            # https://langui.sh/2009/03/07/generating-very-large-primes/
            if n % 2 == 0:
                return False  
            s = n-1
            t = 0
            while s % 2 == 0:
                s = s//2
                t +=1
            k = 0
            while k<5:
                a = random.randrange(2,n-1)
                #a^s is computationally infeasible.  we need a more intelligent approach
                #v = (a**s)%n
                #python's core math module can do modular exponentiation
                v = pow(a,s,n) #where values are (num,exp,mod)
                if v != 1:
                    i=0
                    while v != (n-1):
                        if i == t-1:
                            return False
                        else:
                            i = i+1
                            v = (v**2)%n
                k+=2
            return True
        
        
            
        def return_prime(type):
            """
                1. Generates random number in range
                2. Checks until generated number is a prime and then returns it
            """
            ### Lib method
            if type == "lib":
                return sympy.randprime(2 ** (self.length // 2 - 1), 2 ** (self.length // 2) - 1)
            
            ### Custom method 
            while True:
                potential_prime = random.randrange(2**(self.length // 2 - 1) + 1, 2**(self.length // 2)-1) # <a,b)
                if Rabin_Miller(potential_prime):
                    return potential_prime
                
        
        self.show_info("Generating p")
        p = return_prime("custom")  
        self.show_info(f"Genarated p: {p}")

        self.show_info("Generating q")
        q = return_prime("custom")
        self.show_info(f"Genarated q: {q}")

       
        n = p*q      
        o = (p - 1) * (q - 1) 
        e = 0
        
        self.show_info(f"p - {p} \nq - {q} \nn - {n} \no - {o} \ne - {e}")
        
        self.show_info("generating e \nChecking coprime...")
        while True:
            e = random.randrange(2,min(o-1,2**16))
            #self.show_info(f"Checking coprime {e} with {o}")
            if isCoprime(e, o):
                break
            
        self.show_info("e generated, now counting d")
        d = inverse(e, o)
        self.show_info(f"d counted {d}")
        
        publicKey  = (e,n)
        privateKey = (d,n)
        
        
        self.show_info(f"p - {p} \nq - {q} \nn - {n} \no - {o} \ne - {e} \nd - {d}")
        
        return publicKey,privateKey
        
         
        
    """
    ======================================================================
                RSA Encryption Methods
    ======================================================================
    """
        
    def crypto_ECB(self,data):
        data_length = len(data)
        ciphered_data = b''
        #additional_data = b''
        self.show_info(f"Prediction: {int(math.ceil(data_length/self.block_length))}")
        block_start = 0
        while block_start < data_length:
            block_end = min(block_start + self.block_length,data_length)
            self.show_info(f"Cipher block start {block_start}, block end {block_end}")
            cipher_block = int.from_bytes(data[block_start:block_end], byteorder = "big")   #b'IDAT' -> b'IDA' -> 73821234
                                                                                #        -> b'T'   -> 98373215
            ciphered_block = self.crypto(cipher_block) # 73821234 -> 598212342
                                                       # 98373215 -> 607972514
            self.show_info(f"{cipher_block} -> {ciphered_block}")
            ciphered_block_byte = ciphered_block.to_bytes(self.byte_length, byteorder ='big') #598212342 -> b'SECR'
                                                                                              #607972514 -> b'MESS'
            if block_end == data_length:
                self.last_block_length = block_end - block_start                                                                                  
            self.show_info(f"{data[block_start:block_end]} -> {cipher_block} -> {ciphered_block} -> {ciphered_block_byte}")
            """if block_end == data_length:
                self.last_block_length = block_end - block_start
                ciphered_data += ciphered_block_byte#[0:block_end - block_start]
                #additional_data += ciphered_block_byte[block_end - block_start:]
                break"""
            ciphered_data += ciphered_block_byte#[0:-1]
            #additional_data += ciphered_block_byte[-1:]
            block_start += self.block_length
        #print(f"Additional Data - {additional_data}")
        #ciphered_data += additional_data
        return ciphered_data
    
    def decrypto_ECB(self, data):
        data_length = len(data)
        # print(f"data_len - {data_length}")
        # print(f"byte len - {self.byte_length}")
        assert data_length % self.byte_length == 0, "Invalid length of data to decrypt"
        decrypted_data = b''
        block_start = 0
        while block_start < data_length:
            block_end = block_start + self.byte_length
            
            
            decrypto_block = int.from_bytes(data[block_start:block_end], byteorder = 'big') #b'SECRMESS' -> b'SECR' -> 598212342
                                                                                            #            -> b'MESS' -> 607972514
            decrypted_block = self.decrypto(decrypto_block) # 598212342 -> 73821234
                                                            # 607972514 -> 98373215
            if block_end == data_length:
                decrypted_block_byte = decrypted_block.to_bytes(self.byte_length - 1, byteorder='little') #98373215 -> b'T'
                decrypted_block_byte = decrypted_block_byte[0:self.last_block_length]
            else:
                self.show_info(f"Convert {decrypto_block} ->{decrypted_block}")
                decrypted_block_byte = decrypted_block.to_bytes(self.byte_length - 1, byteorder='big') #73821234 -> b'IDA'
                                                                                                   
            self.show_info(f"{data[block_start:block_end]} -> {decrypto_block} -> {decrypted_block} -> {decrypted_block_byte}")
            decrypted_data += decrypted_block_byte
            block_start += self.byte_length            
        return decrypted_data

    def get_key_data_public(self):
        d_len = (self.publicKey[0].bit_length() + 7 ) // 8         
        last_block_len = self.last_block_length.to_bytes(4, byteorder = 'big')
        print(f"Zapisuje... \nd - {self.publicKey[0]} \nn - {self.publicKey[1]} \nlast_block - {last_block_len}")
        d = self.publicKey[0].to_bytes(d_len, byteorder = 'big')
        n = self.publicKey[1].to_bytes(self.byte_length, byteorder = 'big')
        d_len = d_len.to_bytes(4, byteorder = 'big')  
        n_len = self.byte_length.to_bytes(4, byteorder = 'big')
        
        return d_len+n_len+last_block_len+d+n

    def get_key_data(self):
        d_len = (self.privateKey[0].bit_length() + 7 ) // 8         
        last_block_len = self.last_block_length.to_bytes(4, byteorder = 'big')
        print(f"Zapisuje... \nd - {self.privateKey[0]} \nn - {self.privateKey[1]} \nlast_block - {last_block_len}")
        d = self.privateKey[0].to_bytes(d_len, byteorder = 'big')
        n = self.privateKey[1].to_bytes(self.byte_length, byteorder = 'big')
        d_len = d_len.to_bytes(4, byteorder = 'big')  
        n_len = self.byte_length.to_bytes(4, byteorder = 'big')
        
        return d_len+n_len+last_block_len+d+n

    def generate_nonce(self, length=8):
        """Generate pseudorandom number."""
        return ''.join([str(random.randint(0, 9)) for _ in range(length)])
        
    def crypto_CTR(self, data):
        data_length = len(data)
        ciphered_data = b''
        block_start = 0
        counter = int(self.nonce)
        while block_start < data_length:
            block_end = min(block_start + self.block_length, data_length)
            cipher_counter = self.crypto(counter)
            ciphered_block_byte = (cipher_counter ^ int.from_bytes(
                data[block_start:block_end], byteorder='big')).to_bytes(
                self.byte_length, byteorder='big')
            if block_end == data_length:
                self.last_block_length = block_end - block_start                                                                                  
            ciphered_data += ciphered_block_byte
            counter += 1
            block_start += self.block_length

        return ciphered_data

    def decrypto_CTR(self, data):
        data_length = len(data)
        assert data_length % self.byte_length == 0, "Invalid length of data to decrypt"
        decrypted_data = b''
        block_start = 0
        counter = int(self.nonce)
        while block_start < data_length:
            block_end = block_start + self.byte_length
            cipher_counter = self.crypto(counter)
            decrypto_block = int.from_bytes(data[block_start:block_end], byteorder = 'big') #b'SECRMESS' -> b'SECR' -> 598212342
            decrypted_block_byte = (cipher_counter ^ decrypto_block).to_bytes(
                self.byte_length, byteorder='big')
            decrypted_data += decrypted_block_byte
            block_start += self.block_length
            counter += 1

        return decrypted_data

        
        