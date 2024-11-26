import hashlib
import os

from Crypto.Cipher import AES

ENABLE_DEBUG = False

p = 124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154805420913
OUR_PRIVATE_KEY = 47665984957579041667574354420915791855231781224633825480839364799640816541920020398704318295670597125939823219557406936976558605653848890156197282695284753416331013889219333130014563033939327385021810369771797980097212658862094922812460323018340500982557809442342308422326580550524083403916946335666783110870
THEIR_PUBLIC_KEY = 73914842117566290216672196550715038289712001833386114140093252734764904038406273235020158273335923467463958428415811483524460064011019669658485083107565219187804861342206947570753750239297051980125481910300912765963773917297107612580673784541344610251602691472071001921185319847548765900369812452347685246532

def log(log: str, value: bytes):
    if ENABLE_DEBUG:
        return print(f"\n{log} -> {len(value)} -> {value.hex().upper()} -> {[byte for byte in value]}")

def calculate_encription_key(publickey, privatekey, p):
    V = pow(publickey, privatekey, p)
    S = V.to_bytes(((V.bit_length() + 7) // 8), 'big')
    hash = hashlib.sha256(S).digest()
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

def encrypt_aes_cbc(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return iv + encrypted_bytes

def main():
    key = calculate_encription_key(THEIR_PUBLIC_KEY, OUR_PRIVATE_KEY, p)
    log("key",key) 

    received_message = "f35c1209888fb546e978b66269e4e6b8eea15820151f8e4300d8972efcb99ee7dcfed93c1a568f747f9b81004ca8a7516e7c8d197fd99a2967b3f3d767084e06".upper()
    print(f"Message received -> {received_message}")

    received_bytes = bytes.fromhex(received_message)
    log("received_bytes", received_bytes)
    
    iv = received_bytes[:16]
    log("iv", iv)
    encrypted_text = received_bytes[16:]
    log("encrypted_text", encrypted_text)
    
    decrypted_bytes = decrypt_aes_cbc(key, iv, encrypted_text)
    log("decrypted_bytes", decrypted_bytes)

    decrypted_message = decrypted_bytes.decode(encoding='utf-8')
    print(f"Message decrypted -> {decrypted_message}")

    backwards_message = decrypted_message[::-1]
    print(f"Message backwards -> {backwards_message}")

    encrypted_bytes = encrypt_aes_cbc(key, backwards_message)
    log("encrypted_bytes", encrypted_bytes)

    encrypted_message = encrypted_bytes.hex().upper()
    print(f"Message to be sent -> {encrypted_message}")

    # validação do resultado
    # msg_sent = bytes.fromhex(encrypted_message)
    # print(f"Decripting sent message -> {decrypt_aes_cbc(key, msg_sent[:16], msg_sent[16:]).decode(encoding='utf-8')}")

main()