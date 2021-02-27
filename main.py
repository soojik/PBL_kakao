import sys
from extract import extract
from kakao_decrypt import decrypt
import hashlib
import base64
import argparse
import csv
import pandas as pd
from Crypto.Cipher import AES
import binascii

def main():
    import argparse

    parser = argparse.ArgumentParser(description='extract and decrypt kakaotalk message.')
    parser.add_argument('-f', '--file', 
                        type = str,
                        default = 'image.dd',
                        help = 'File name to extract.')

    parser.add_argument('-e', '--extracrt', 
                        dest = 'decrypt', 
                        action = 'store_false', 
                        help = 'Extract kakaotalk message option')

    parser.add_argument('-d', '--decrypt', 
                        dest = 'extract', 
                        action = 'store_false', 
                        help = 'Decrypt kakaotalk message option')

    args = parser.parse_args()

    if (args.extract):
        extract()
    if (args.decrypt):
        decrypt()

main()
