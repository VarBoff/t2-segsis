import hashlib

from Crypto.Cipher import AES

import os

# 2hex = 8bit = 1byte
p = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371

# Nossas chaves
our_privatekey = 94946190165624987909451889947569482316727011621670205933282622949920315206300567266890423160424505229274778049847942082514824557478809823382196738843182848281900550419430295686449023534526006264427473244890513085974259327384968071185075479975762572966317665139737755894838553090970321459989622612760867810206
their_publickey = 0x73B0F92474CE681F0990F666B6691E8837AE99F2D97853BC5449BD1E1E6B425BD3812C4D57B8509D162599D5543863EB2FECEF541591F033E2F5A6122592DB26B8A6B1BEE9C7402B23682EE710242847FF84336FF9505E827D2A264BCA94F0E3B10BD933FC29CD882F5C6230F9F7FF11BD30267D8A962B8B62361DEFB490FC57

# chave velha
# their_publickey = 0x7D4B4D8B27EEC16AE4C7EE73A3B064049276F8721ADA552F70D48807BA37F50F31F9C02D290F92757B9FB17D4E02893AFEA2DE622726A744C47050C0C0E98B03E11467935CDC1F3189C62717C433753406CD1D4D5569265B6E152FE45A159F313686B7A30CEFCEB59200BE1D9B1A4B80F4D6B6F8C4E536ACB862F00F36B6D5F2FC67397C8459EAA095CF47371396437CC11CD08417A3C0D4E89C9AC7229B1C267308CF1C432DD7C3F0875D596655C505F15C7CFA9902AA35C79D8D1A2A59B68EE51FE140686E1FC5EA9AAB027F4DBECEC7A0D4ABBC5A0ACD15449B589E9483B825AFC366C7AC83E686790F6803049174CF82683BAEE75130EB95ED06

# chave da vittoria
# our_privatekey = 98189241835472626433774145815792375361604408279238751806179382458324455907184
# their_publickey = 0x028A53DE2CEFC97C8A5CA20A2884DAE35DDACA52264876C913D2F529C925A341A699D5A16FA7E3FBD97599B9C51F4E0F598E4EDC5E9441D3C38960216410E2D30D9F084E1CEADFD51C237384CEA85D70EA41F90BEA557855D07FDA50B9705AA70DDADE7379D088BFB919BDAB87A82C631E2AAAD08A0636B6BA96B7E43EFA9790

def calculate_encription_key(publickey, privatekey, p):
    v = pow(publickey, privatekey, p)
    s = v.to_bytes(((v.bit_length() + 7) // 8) + 1)
    hash = hashlib.sha256(s).digest()
    return hash[-16:]

def pad(data, block_size=16):
    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length] * pad_length)

def unpad(data, block_size=16):
    pad_length = min(data[-1], block_size)
    return data[:-pad_length]

def decrypt_aes_cbc(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    original_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return original_message

def encript_aes_cbc(plaintext, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_text = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv.hex() + encrypted_text.hex()

def main():
    key = calculate_encription_key(their_publickey, our_privatekey, p)

    # Nossa MSG
    received_message = bytes.fromhex("f14c3e0f30afe2b3d6ca2e5ac9d8cd4eadb5716236ee27ff7895cfca62e502eaaea51a9cc5a549758fe5339de292a84b925d7dcd7250fb50f3bf9e8c886f84f4")
    
    # msg velha
    # received_message = bytes.fromhex("e3f706aea652d6d0b6a43ac8565295c154c551b146020e6f573d3d11fcf2b6550932516f7a70de1f995a502ef6895c05f33ab66891acc5f5e780434fdf43f4bf")
    
    # msg da vittoria
    # received_message = bytes.fromhex("9eb60e9dd89e220dbad765babb7abe3a7efa1dcfa2990e56743167e476a7a2f19a2694214d06fc9cc669c6ee28136acd3d70b461be5bbf03cb72a01b20bd0838")
    
    iv = received_message[:16]
    encrypted_text = received_message[16:]

    print(f"\nkey = {len(key)} -> {key.hex().upper()} -> {[byte for byte in key]}")
    print(f"\niv = {len(iv)} -> {iv.hex().upper()} -> {[byte for byte in iv]}")
    print(f"\nencrypted_text = {len(encrypted_text)} -> {encrypted_text.hex().upper()} -> {[byte for byte in encrypted_text]}")

    decrypted_text = decrypt_aes_cbc(key, iv, encrypted_text)

    print(f"\ndecrypted_text = {len(decrypted_text)} -> {decrypted_text.hex().upper()} -> {[byte for byte in decrypted_text]}")
    print(f"\n{decrypted_text.decode(encoding='utf-8', errors='replace')=}")

main()