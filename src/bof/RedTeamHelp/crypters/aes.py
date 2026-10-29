import sys
from Cryptodome.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
    block_size = AES.block_size
    padding_size = block_size - len(s) % block_size
    padding = bytes([padding_size] * padding_size)
    return s + padding

def aesenc(plaintext, key):

    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext)
    cipher = AES.new(k, AES.MODE_CBC, iv)

    return cipher.encrypt(plaintext)

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)
print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:].zfill(2) for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:].zfill(2) for x in ciphertext) + ' };')
print('unsigned int payload_len = sizeof(payload);')
decrypt_function = '''
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
        return -1;
    }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)){
        return -1;              
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, payload, &payload_len)){
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}
'''
print ('Decryption function: ',decrypt_function)
print('decrypt function call is:  AESDecrypt((char *) payload, calc_len, key, sizeof(key));')
