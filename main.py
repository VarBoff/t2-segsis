import hashlib
import gmpy2

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# 2hex = 8bit = 1byte
p = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

vic_our_privatekey = 98189241835472626433774145815792375361604408279238751806179382458324455907184
vic_their_publickey = 0x028A53DE2CEFC97C8A5CA20A2884DAE35DDACA52264876C913D2F529C925A341A699D5A16FA7E3FBD97599B9C51F4E0F598E4EDC5E9441D3C38960216410E2D30D9F084E1CEADFD51C237384CEA85D70EA41F90BEA557855D07FDA50B9705AA70DDADE7379D088BFB919BDAB87A82C631E2AAAD08A0636B6BA96B7E43EFA9790
our_privatekey = 0x8735367fecc56a4bbf4ba1842fd5f3c6050acc64e97e1669dc6a76c8937d93734fe64c584eff1514d29033aefc76cd8c9b0366876bde0d0020e74b286c6a06461eff01872ac1ebee3b90f1bcf18a2b64fc32ae93f351c4910b672e4cc96e3d63d81c8841ab698f9c455f39e6d65e2abc52907104ad9da3824c6a53e8235aab9e
their_publickey = 0x73B0F92474CE681F0990F666B6691E8837AE99F2D97853BC5449BD1E1E6B425BD3812C4D57B8509D162599D5543863EB2FECEF541591F033E2F5A6122592DB26B8A6B1BEE9C7402B23682EE710242847FF84336FF9505E827D2A264BCA94F0E3B10BD933FC29CD882F5C6230F9F7FF11BD30267D8A962B8B62361DEFB490FC57
# old_their_publickey = 0x7D4B4D8B27EEC16AE4C7EE73A3B064049276F8721ADA552F70D48807BA37F50F31F9C02D290F92757B9FB17D4E02893AFEA2DE622726A744C47050C0C0E98B03E11467935CDC1F3189C62717C433753406CD1D4D5569265B6E152FE45A159F313686B7A30CEFCEB59200BE1D9B1A4B80F4D6B6F8C4E536ACB862F00F36B6D5F2FC67397C8459EAA095CF47371396437CC11CD08417A3C0D4E89C9AC7229B1C267308CF1C432DD7C3F0875D596655C505F15C7CFA9902AA35C79D8D1A2A59B68EE51FE140686E1FC5EA9AAB027F4DBECEC7A0D4ABBC5A0ACD15449B589E9483B825AFC366C7AC83E686790F6803049174CF82683BAEE75130EB95ED06

def calculate_encription_key(publickey, privatekey, p):
    v = pow(publickey, privatekey, p)
    s = v.to_bytes((v.bit_length() + 7) // 8)
    return hashlib.sha256(s).digest()[-16:]

# def pad(data, block_size=16):
#     pad_length = block_size - (len(data) % block_size)
#     return data + bytes([pad_length] * pad_length)

# def unpad(data):
#     pad_length = data[-1]
#     return data[:-pad_length]

def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original_message = cipher.decrypt(ciphertext)
    return original_message

# def decrypt_aes_cbc(key, iv, ciphertext):
#     cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
#     decryptor = cipher.decryptor()

#     # Decrypt and remove padding
#     # padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
#     # unpadder = PKCS7(128).unpadder()
#     # plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

#     plaintext = decryptor.update(ciphertext) + decryptor.finalize()

#     return plaintext

def main():
    key = calculate_encription_key(their_publickey, our_privatekey, p)

    received_message = bytes.fromhex("f14c3e0f30afe2b3d6ca2e5ac9d8cd4eadb5716236ee27ff7895cfca62e502eaaea51a9cc5a549758fe5339de292a84b925d7dcd7250fb50f3bf9e8c886f84f4")
    vic_received_message = bytes.fromhex("9eb60e9dd89e220dbad765babb7abe3a7efa1dcfa2990e56743167e476a7a2f19a2694214d06fc9cc669c6ee28136acd3d70b461be5bbf03cb72a01b20bd0838")
    
    # old_received_message = bytes.fromhex("e3f706aea652d6d0b6a43ac8565295c154c551b146020e6f573d3d11fcf2b6550932516f7a70de1f995a502ef6895c05f33ab66891acc5f5e780434fdf43f4bf")
    
    iv = received_message[:16]
    encrypted_text = received_message[16:]

    print(f"\nkey = {len(key)} -> {key.hex().upper()} -> {[byte for byte in key]}")
    print(f"\niv = {len(iv)} -> {iv.hex().upper()} -> {[byte for byte in iv]}")
    print(f"\nencrypted_text = {len(encrypted_text)} -> {encrypted_text.hex().upper()} -> {[byte for byte in encrypted_text]}")

    decrypted_text = decrypt_aes_cbc(key, iv, encrypted_text)

    print(f"\ndecrypted_text = {len(decrypted_text)} -> {decrypted_text.hex().upper()} -> {[byte for byte in decrypted_text]}")
    print(f"\n{decrypted_text.decode(encoding='utf-8', errors='replace')=}")

main()