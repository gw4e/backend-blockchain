import Crypto
from Crypto.PublicKey import RSA

from src.blockchain.utils import serialize, deserialize


def test_serialize_deserialize():
    random = Crypto.Random.new().read
    private_key = RSA.generate(1024, random)
    public_key = private_key.publickey()

    s_private_key = serialize(private_key)
    ds_private_key = deserialize(s_private_key)
    ds_public_key = ds_private_key.publickey()
    assert ds_public_key == public_key
