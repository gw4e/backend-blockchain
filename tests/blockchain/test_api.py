import Crypto
from Crypto.PublicKey import RSA
from dotenv import load_dotenv

from src.blockchain.api import Api
from src.blockchain.block_chain import BlockChain

load_dotenv()


def test_add_transaction(block_chain_without_owner):
    random = Crypto.Random.new().read
    from_address_private_key = RSA.generate(1024, random)
    from_address = from_address_private_key.publickey()
    block_chain_without_owner.setOwner(from_address_private_key)
    block_chain_without_owner.mine_pending_transactions(True)

    random = Crypto.Random.new().read
    to_address_private_key = RSA.generate(1024, random)
    to_address = to_address_private_key.publickey()

    api = Api(block_chain_without_owner)
    api.add_transaction(from_address, to_address, from_address_private_key, 2)
    assert block_chain_without_owner.get_pool_transactions().is_there_transaction_pending_for(from_address)


# noinspection PyTypeChecker
def test_describe_blockchain(block_chain_with_mined_blocks):
    block_chain = block_chain_with_mined_blocks["blockchain"]
    api = Api(block_chain)
    json_data = api.describe_blockchain()

    #
    assert len((json_data["genesis_transaction"]["uuid"])) > 0
    assert int((json_data["genesis_transaction"]["amount"])) >= 0
    assert len((json_data["genesis_transaction"]["from_address"])) > 0
    assert len((json_data["genesis_transaction"]["to_address"])) > 0
    assert len((json_data["genesis_transaction"]["signature"])) > 0
    #
    assert len((json_data["chain"])) > 0
    assert int((json_data["chain"][0]["nonce"])) == 0
    assert len((json_data["chain"][0]["timestamp"])) > 0
    assert len((json_data["chain"][0]["previous_hash"])) > 0
    assert len((json_data["chain"][0]["hash"])) > 0
    assert len((json_data["chain"][0]["transactions"])) > 0
    assert len((json_data["chain"][0]["transactions"][0]["uuid"])) > 0
    assert int((json_data["chain"][0]["transactions"][0]["amount"])) >= 0
    assert len((json_data["chain"][0]["transactions"][0]["to_address"])) > 0
    assert len((json_data["chain"][0]["transactions"][0]["signature"])) > 0
    #
    assert len((json_data["reward_key"])) > 0
    assert len((json_data["mining_address"])) > 0
    assert int((json_data["difficulty"])) > 0
    assert int((json_data["mining_reward_amount"])) > 0


def test_get_block_chain_as_json_string(monkeypatch, block_chain_with_mined_blocks):
    calls_args = []

    def my_request(blockchain, **kwargs):
        calls_args.append(blockchain)

    monkeypatch.setattr(BlockChain, 'to_json_string', my_request)

    block_chain = block_chain_with_mined_blocks["blockchain"]
    api = Api(block_chain)
    api.get_block_chain_as_json_string()
    assert calls_args[0] == block_chain
