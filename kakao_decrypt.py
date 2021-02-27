import hashlib
import base64
import argparse
import csv
import pandas as pd
from Crypto.Cipher import AES
import binascii
import ast

def deriveKey(password, salt, iterations, dkeySize):
    password = (password + b'\0').decode('ascii').encode('utf-16-be')

    hasher = hashlib.sha1()
    v = hasher.block_size
    u = hasher.digest_size

    D = [ 1 ] * v
    S = [ 0 ] * v * int((len(salt) + v - 1) / v)
    for i in range(0, len(S)):
        S[i] = salt[i % len(salt)]
    P = [ 0 ] * v * int((len(password) + v - 1) / v)
    for i in range(0, len(P)):
        P[i] = password[i % len(password)]

    I = S + P

    B = [ 0 ] * v
    c = int((dkeySize + u - 1) / u)

    dKey = [0] * dkeySize
    for i in range(1, c+1):
        hasher = hashlib.sha1()
        hasher.update(bytes(D))
        hasher.update(bytes(I))
        A = hasher.digest()

        for j in range(1, iterations):
            hasher = hashlib.sha1()
            hasher.update(A)
            A = hasher.digest()
            
        A = list(A)
        for j in range(0, len(B)):
            B[j] = A[j % len(A)]

        for j in range(0, int(len(I)/v)):
            pkcs16adjust(I, j * v, B)

        start = (i - 1) * u
        if i == c:
            dKey[start : dkeySize] = A[0 : dkeySize-start]
        else:
            dKey[start : start+len(A)] = A[0 : len(A)]
    return bytes(dKey)

def pkcs16adjust(a, aOff, b):
    x = (b[len(b) - 1] & 0xff) + (a[aOff + len(b) - 1] & 0xff) + 1
    a[aOff + len(b) - 1] = x % 256
    x = x >> 8;

    for i in range(len(b)-2, -1, -1):
        x = x + (b[i] & 0xff) + (a[aOff + i] & 0xff)
        a[aOff + i] = x % 256
        x = x >> 8

def decrypt():
    try:
        df = pd.read_csv('kakao.csv')
    except:
        print('can\'t open file \'kakao.csv\'.\nextract first.\n')
        return 
  
    for i in ['time', 'cipher', 'enc']:
        num = 0
        for j in df[i]:
            if (len(j) < 3):
                num = num+1
                continue
            j = j[2:-1]
            df[i][num] = j
            num = num+1

    df = df.drop_duplicates()
    df = df.set_index('time') 
    df = df.sort_index()
    
    prefixes = ['','','12','24','18','30','36','12','48','7','35','40','17','23','29',
                'isabel','kale','sulli','van','merry','kyle','james', 'maddux',
                'tony', 'hayden', 'paul', 'elijah', 'dorothy', 'sally', 'bran', 'extr.ursra']

    decrypt_df = pd.DataFrame(columns = ['time', 'enc','user_id', 'cipher', 'decrypt','dir'])
    dec_error = 'error'

    for i in range(len(df)):
        encType = int(df['enc'][i])
        b64_ciphertext= df['cipher'][i]
        user_id =df['sender'][i]
       
        key = b'\x16\x08\x09\x6f\x02\x17\x2b\x08\x21\x21\x0a\x10\x03\x03\x07\x06'
        iv = b'\x0f\x08\x01\x00\x19\x47\x25\xdc\x15\xf5\x17\xe0\xe1\x15\x0c\x35'
    
        try:
            salt = prefixes[encType] + str(user_id)
            salt = salt[0:16]
        except IndexError:
            raise ValueError('Unsupported encoding type %i' % encType)
    
        salt = salt + '\0' * (16 - len(salt))
        salt = salt.encode('UTF-8')
    
        iterations = 2
        dkeySize = 32
        key = deriveKey(key, salt, iterations, dkeySize)
    
        media_dir = ''
        if '==' in b64_ciphertext:
            media_dir_cipher = b64_ciphertext[b64_ciphertext.find("==")+2:]
            try:
                encoder = AES.new(key, AES.MODE_CBC, iv)
                media_dir_ciphertext = base64.b64decode(media_dir_cipher)
                media_dir_padded = encoder.decrypt(media_dir_ciphertext)
                media_dir_plaintext = media_dir_padded[:-media_dir_padded[-1]]
                media_dir = media_dir_plaintext.decode('UTF-8')
            except:
                pass
     
        try:
            encoder = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = base64.b64decode(b64_ciphertext)
            padded = encoder.decrypt(ciphertext)
            plaintext = padded[:-padded[-1]]
        except:
            plaintext = 'error'
    
        try:
            dap = plaintext.decode('UTF-8')
        except:
            dap = plaintext
            pass
    
        decrypt_df.loc[i] = [df.index[i], df['enc'][i], df['sender'][i], df['cipher'][i], dap, media_dir]

    decrypt_df= decrypt_df.set_index('time')
    decrypt_df.to_csv('kakao_decrypt.csv', encoding='utf-8-sig')
    print("✔Create kakao_decrypt.csv\n")
