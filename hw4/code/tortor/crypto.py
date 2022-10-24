
import rsa
from math import ceil


CRYPT_EFFECTIVE_SIZE = 245
CRYPT_SIZE = 256


def blob_rsa_enc(mbytes, pubkey):
    """
    Used for encrypting large strings with RSA
    The RSA algorithm only allows encrypting byte sequences shorter than its
    key size. In practice, the maximum possible size is even lower than the
    key size as there are some byte paddings in order. This function encrypts
    the given byte sequence block by block and returns the RSA encrypted
    cipher-text from it which is ~8% longer.

    :param mbytes: bytes - plain-text
    :param pubkey: rsa.PublicKey - encryption pubkey
    :return: cipher-text
    """
    return b"".join([rsa.encrypt(mbytes[i*CRYPT_EFFECTIVE_SIZE:(i+1)*CRYPT_EFFECTIVE_SIZE], pub_key=pubkey)
                     for i in range(int(ceil(len(mbytes) / CRYPT_EFFECTIVE_SIZE)))])


def blob_rsa_dec(mbytes, privkey):
    """
    Used for decrypting larger byte sequences encrypted using the blob_rsa_enc()
    method above.
    :param mbytes: bytes - cipher-text
    :param privkey: rsa.PrivateKey - privkey needed for decryption
    :return: bytes - plain-text
    """
    return b"".join([rsa.decrypt(mbytes[i*CRYPT_SIZE:(i+1)*CRYPT_SIZE], priv_key=privkey)
                    for i in range(int(len(mbytes) / CRYPT_SIZE))])


if __name__ == "__main__":

    s = b"""Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas quis porta nulla. Nulla facilisi. 
    Suspendisse pulvinar ante in pretium pharetra. Fusce ac ante ipsum. Donec ac maximus mauris. Donec aliquam odio 
    at rhoncus volutpat. Morbi nunc nulla, congue sed tristique a, posuerea et orci. Maecenas vitae lacinia mi. 
    Maecenas cursus ultrices risus, at egestas velit. Pellentesque tincidunt elementum dolor. Nam consectetur lectus 
    purus, non cursus tellus venenatis eu. Aenean rutrum euismod felis, in malesuada mi consectetur sit amet. """

    pub, priv = rsa.newkeys(2048, poolsize=8)
    a = blob_rsa_enc(s, pub)
    b = blob_rsa_dec(a, priv)

    print("Success" if b == s else "Failure")




