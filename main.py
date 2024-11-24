import hashlib
import gmpy2

from Crypto.Cipher import AES

# 2hex = 8bit = 1byte
g = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
p = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

our_privatekey = 0x8735367fecc56a4bbf4ba1842fd5f3c6050acc64e97e1669dc6a76c8937d93734fe64c584eff1514d29033aefc76cd8c9b0366876bde0d0020e74b286c6a06461eff01872ac1ebee3b90f1bcf18a2b64fc32ae93f351c4910b672e4cc96e3d63d81c8841ab698f9c455f39e6d65e2abc52907104ad9da3824c6a53e8235aab9e
their_publickey = 0x73B0F92474CE681F0990F666B6691E8837AE99F2D97853BC5449BD1E1E6B425BD3812C4D57B8509D162599D5543863EB2FECEF541591F033E2F5A6122592DB26B8A6B1BEE9C7402B23682EE710242847FF84336FF9505E827D2A264BCA94F0E3B10BD933FC29CD882F5C6230F9F7FF11BD30267D8A962B8B62361DEFB490FC57

def calculate_encription_key(publickey, privatekey, p):
    common_key = gmpy2.powmod(publickey, privatekey, p)
    common_key_bytes = common_key.to_bytes((common_key.bit_length() + 7) // 8, byteorder='big')
    return hashlib.sha256(common_key_bytes).digest()[:16]

def pad(data, block_size=16):
    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length] * pad_length)

def unpad(data):
    pad_length = data[-1]
    return data[:-pad_length]

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def simple_aes(block, key):
    # Se for usar lib, colocar aq a implementação
    return xor_bytes(block, key)

def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    original_message = unpad(cipher.decrypt(ciphertext))
    return original_message

# def decrypt_aes_cbc(key, iv, ciphertext):
#     plaintext = b""
#     previous_block = iv

#     for i in range(0, len(ciphertext), 16):
#         block = ciphertext[i:i + 16]
#         decrypted_block = simple_aes(block, key)
#         decrypted_block = xor_bytes(decrypted_block, previous_block)
#         plaintext += decrypted_block
#         previous_block = block

#     return unpad(plaintext, 16)

def main():
    key = calculate_encription_key(their_publickey, our_privatekey, p)

    received_message = bytes.fromhex("f14c3e0f30afe2b3d6ca2e5ac9d8cd4eadb5716236ee27ff7895cfca62e502eaaea51a9cc5a549758fe5339de292a84b925d7dcd7250fb50f3bf9e8c886f84f4")

    iv = received_message[:16]
    ciphertext = received_message[16:]

    print(f"{len(key)=}, {key=}")
    print(f"{len(iv)=}, {iv=}")
    print(f"{len(ciphertext)=}, {ciphertext=}")

    print(f'decrypted={decrypt_aes_cbc(key, iv, ciphertext).decode()}')

main()