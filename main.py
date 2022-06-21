from classes.png import PNG
import copy
from classes.chunk import Chunk
from classes.rsa import RSA
import matplotlib.pyplot as plt
import time

img_name = "linux.png"

def extract_data_from_chunk(file):
    length = file.read(4)  
    t = file.read(4)
    data = file.read(int.from_bytes(length, byteorder='big'))
    crc = file.read(4)
    
    return Chunk(length, t, data, crc)

def test_rsa():
    rsa = RSA(32)
    rsa.generate_keys()

    print("Key Created")
    time.sleep(0.1)
    crypto = rsa.crypto(5160001)

    print("Crypto done")
    time.sleep(0.1)
    decrypto = rsa.decrypto(crypto)

    print("decrypto done")
    time.sleep(0.1)

    data_to_cipher = b'IDAT'
    ciphered = rsa.crypto_ECB(data_to_cipher)
    print(f"org len - {len(data_to_cipher)}\nCiphered len - {len(ciphered)}")

    decrypted = rsa.decrypto_ECB(ciphered)
# initialize png to store all data

def cipher_image(png,key_len):
    png.process_IDAT_image()
    png.write_encrypted_image_ECB(key_len)
    png.show_image()

def decipher_image(png):
    img = plt.imread(img_name)
    plt.figure(num=1)
    plt.imshow(img)
    png.read_encrypted_image_ECB()

def cipher_image_CTR(png,key_len):
    png.process_IDAT_image()
    png.write_encrypted_image_CTR(key_len)
    png.show_image()

def decipher_image_CTR(png):
    img = plt.imread(img_name)
    plt.figure(num=1)
    plt.imshow(img)
    png.read_encrypted_image_CTR()



png = PNG()
img_name = "linux.png"
mode = 2 # 1 - cipher, 2 - decipher
key_length = 128
use_ECB = False

with open(img_name, 'rb') as f:
    b = f.read(8)

    assert b == png.first_eight_bytes, "This ain't PNG"
    print('This is a PNG file!')


    while True:
        c = extract_data_from_chunk(f)
        png.chunks.append(c)
        if c.type == b'IEND':
            png.read_IEND_message(f)
            break

png.read_data_from_chunks()
#png.process_IDAT_image()
#png.write_secret_message("To wiadamosc sekretna jest")

#png.write_encrypted_image_ECB(40)
#png.read_encrypted_image_ECB()
if use_ECB:
    if mode == 1: cipher_image(png,key_length)
    elif mode == 2 : decipher_image(png)
    png.show_write_new_img()
    plt.show()
else:
    cipher_image_CTR(png,key_length)
    png.show_write_new_img()
    
    png2 = PNG(copy.deepcopy(png.rsa))
    img_name = 'new_file.png'
    with open(img_name, 'rb') as f:
        b = f.read(8)

        assert b == png2.first_eight_bytes, "This ain't PNG"
        print('This is a PNG file!')


        while True:
            c = extract_data_from_chunk(f)
            png2.chunks.append(c)
            if c.type == b'IEND':
                png2.read_IEND_message(f)
                break

    png2.read_data_from_chunks()
    decipher_image_CTR(png2)
    png2.show_write_new_img()
    plt.show()
#png.show_image()
#png.show_spectrum()
#png.delete_ancillary_chunks()
#png.delete_chunks()