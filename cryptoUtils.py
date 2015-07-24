import base64
import os
from Crypto.Cipher import AES
from configparser import ConfigParser
from Crypto.Hash import SHA512

LIB_PATH = os.path.split(os.path.realpath(__file__))[0]
PASSPHRASE = LIB_PATH+'/../etc/snmp/snmpv3_user.properties'

def encryptData(str_to_encrypt):
    _METHOD_ = 'cryptoUtils.encryptData'
    BLOCK_SIZE = 32

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '{'

    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

    # Read secret key from file.

    passphrase = read_passphrase()

    # create a cipher object using the random secret
    cipher = AES.new(passphrase)

    # encode a string
    str_to_encrypt = EncodeAES(cipher, str_to_encrypt)

    return str_to_encrypt.decode("utf-8")

def decryptData(str_to_decrypt):
    _METHOD_ = 'cryptoUtils.decryptData'
    BLOCK_SIZE = 32

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = b'{'

    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # one-liners to encrypt/encode and decrypt/decode a string
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    # Read secret key from file.

    passphrase = read_passphrase()

    # create a cipher object using the random secret
    cipher = AES.new(passphrase)

    # decode the encoded string
    decoded = DecodeAES(cipher, str_to_decrypt).decode("utf-8")

    return decoded

def read_passphrase():
    _METHOD_ = 'cryptoUtils.read_passphrase'
    if os.path.exists(PASSPHRASE):
        parser = ConfigParser()
        parser.read(PASSPHRASE)
        passphrase = parser.get('CIPHER', 'AES_KEY')
        # Hash the passphrase using a sha512 algorithm and 256 keysize It returns the hashed string.
        key_hash = ''
        unicode_value = passphrase.encode('utf-8')
        hashobj = SHA512.new()
        hashobj.update(unicode_value)
        hash_value = hashobj.hexdigest()
        key_hash = hash_value[len(hash_value) - ((256 // 8)):
                             len(hash_value)]

    return key_hash
