import binascii

from Crypto.PublicKey import RSA


def serialize(key):
    if key is None or (type(key) == str and len(key) == 0):
        return ""
    return binascii.hexlify(key.exportKey(format='DER')).decode('ascii')


def deserialize(serialized_key):
    z = binascii.unhexlify(serialized_key)
    return RSA.importKey(z)

# if __name__ == '__main__':
#     random = Crypto.Random.new().read
#     private_key = RSA.generate(1024, random)
#     public_key = private_key.publickey()
#     print(f"private_key: {serialize(private_key)}")
#     print(f"public_key: {serialize(public_key)}")
#
#     msg = b'A message for encryption'
#     encryptor = PKCS1_OAEP.new(public_key)
#     encrypted = encryptor.encrypt(msg)
#     print("Encrypted:", binascii.hexlify(encrypted))
#
#     decryptor = PKCS1_OAEP.new(private_key)
#     decrypted = decryptor.decrypt(encrypted)
#     print('Decrypted:', decrypted)
#
#     s_private_key = serialize(private_key)
#     ds_private_key = deserialize(s_private_key)
#     ds_public_key = ds_private_key.publickey()
#     if (ds_public_key == public_key):
#         print("same public key !")
#     msg2 = b'A second message for encryption'
#     encryptor2 = PKCS1_OAEP.new(ds_public_key)
#     encrypted2 = encryptor2.encrypt(msg2)
#     print("Encrypted:", binascii.hexlify(encrypted2))
#
#     decryptor2 = PKCS1_OAEP.new(ds_private_key)
#     decrypted2 = decryptor2.decrypt(encrypted2)
#     print('Decrypted:', decrypted2)
#
#
