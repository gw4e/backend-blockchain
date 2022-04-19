import logging
import os
from datetime import date

import Crypto
import pytest
from Crypto.PublicKey import RSA
from dotenv import load_dotenv

from src.blockchain.block_chain import BlockChain, Transaction, CreditCardTransaction


def setup_tests():
    load_dotenv()
    logging.basicConfig(format="%(asctime)s: %(message)s", level=logging.INFO, datefmt="%H:%M:%S")
    if os.getenv("GENESIS_FILE_LOCATION") is None or len(os.getenv("GENESIS_FILE_LOCATION")) == 0:
        raise Exception(
            'You did not set the GENESIS_FILE_LOCATION environment variable in the .env file. See the readme')


setup_tests()


@pytest.fixture
def block_chain_without_owner():
    block_chain = BlockChain.load_from_store(10)
    block_chain.setOwner(None)
    assert len(block_chain.get_chain_of_blocks()) == 1
    return block_chain


@pytest.fixture
def client_1(block_chain_without_owner):
    random = Crypto.Random.new().read
    client_1 = RSA.generate(1024, random)
    block_chain_without_owner.setOwner(client_1)
    for index in range(0, 10):
        block_chain_without_owner.mine_pending_transactions(True)
    assert block_chain_without_owner.get_balance_for_address(client_1.publickey()) == 100  # 10 * mining_times
    block_chain_without_owner.setOwner(None)
    return client_1


@pytest.fixture
def client_2(block_chain_without_owner):
    random = Crypto.Random.new().read
    client_2 = RSA.generate(1024, random)
    block_chain_without_owner.setOwner(client_2)
    for index in range(0, 5):
        block_chain_without_owner.mine_pending_transactions(True)
    assert block_chain_without_owner.get_balance_for_address(client_2.publickey()) == 50  # 10 * mining_times
    block_chain_without_owner.setOwner(None)
    return client_2


@pytest.fixture
def client_cc(block_chain_without_owner):
    random = Crypto.Random.new().read
    client_cc = RSA.generate(1024, random)
    assert block_chain_without_owner.get_balance_for_address(client_cc.publickey()) == 0
    return client_cc


@pytest.fixture
def block_chain_with_mined_blocks(block_chain_without_owner, client_1, client_2, client_cc):
    tx = Transaction(client_1.publickey(), client_2.publickey(), 30)
    tx.sign_transaction(client_1)
    block_chain_without_owner.add_to_pending_transactions(tx)
    tx2 = Transaction(client_2.publickey(), client_1.publickey(), 10)
    tx2.sign_transaction(client_2)
    block_chain_without_owner.add_to_pending_transactions(tx2)
    cc_transaction = CreditCardTransaction(client_cc.publickey(), client_cc.publickey(), 10)
    cc_transaction.set_data("John Doe", "4387729175443174", date.fromisoformat('2027-08-31'), 302)
    cc_transaction.sign_transaction(client_cc)
    block_chain_without_owner.add_to_pending_transactions(cc_transaction)
    #
    random = Crypto.Random.new().read
    miner_private_key = RSA.generate(1024, random)
    block_chain_without_owner.setOwner(miner_private_key)
    #
    block_chain_without_owner.mine_pending_transactions(True)
    assert block_chain_without_owner.get_pool_transactions().is_empty()
    # 17 blocks = 11 for client_1 , 5 for client_2 , 1 for (tx, tx2)
    assert len(block_chain_without_owner.get_chain_of_blocks()) == 17
    return {
        "blockchain": block_chain_without_owner,
        "client_1": client_1,
        "client_2": client_2,
        "miner": miner_private_key
    }


@pytest.fixture
def block_chain_with_ready_to_mine_block(block_chain_without_owner, client_1, client_2):
    tx = Transaction(client_1.publickey(), client_2.publickey(), 30)
    tx.sign_transaction(client_1)
    block_chain_without_owner.add_to_pending_transactions(tx)
    tx2 = Transaction(client_2.publickey(), client_1.publickey(), 10)
    tx2.sign_transaction(client_2)
    block_chain_without_owner.add_to_pending_transactions(tx2)
    assert block_chain_without_owner.get_pool_transactions().size() == 2
    return {
        "blockchain": block_chain_without_owner,
        "client_1": client_1,
        "client_2": client_2
    }


@pytest.fixture
def invalid_transaction_in_block(block_chain_with_mined_blocks, client_1, client_2):
    last_block = block_chain_with_mined_blocks["blockchain"].get_chain_of_blocks()[-1]
    last_transaction = last_block.get_transactions()[-1]
    assert not last_transaction.is_reward()
    # tamper the transaction
    last_transaction._amount = 1000
    return last_block


@pytest.fixture
def block_chain_with_sized_mined_blocks(blocks_length):
    def create():
        random = Crypto.Random.new().read
        return RSA.generate(1024, random)

    def create_transaction(client_1, client_2, amount):
        transaction = Transaction(client_1.publickey(), client_2.publickey(), amount)
        transaction.sign_transaction(client_1)
        return transaction

    def feed_block_chain_with_blocks(block_chain, chain_size, pending_transactions_count):
        client_1 = create()
        client_2 = create()
        for ind in range(0, chain_size):
            transaction = create_transaction(client_1, client_2, 0)
            block_chain.add_to_pending_transactions(transaction)
            block_chain.mine_pending_transactions(True)
        for ind in range(0, pending_transactions_count):
            transaction = create_transaction(create(), create(), 0)
            block_chain.add_to_pending_transactions(transaction)

    #
    result = []
    for index in range(0, len(blocks_length)):
        block_chain = BlockChain.load_from_store(10)
        block_chain.setOwner(create())
        # blocks_length[index] tells how many block(s) should we have in the current block_chain
        # pending_transactions_count is set to blocks_length[index] because I'm a lazy guy :-)
        feed_block_chain_with_blocks(block_chain, blocks_length[index], blocks_length[index])
        result.append(block_chain)
    return result


@pytest.fixture
def cc_transaction(client_cc):
    # credit card transac is someone using its cc to buy crypto money
    # we impose that wallet source and target are the same
    cc_transaction = CreditCardTransaction(client_cc.publickey(), client_cc.publickey(), 10)
    cc_transaction.set_data("Mary Doe", "4387729175443174", date.fromisoformat('2027-08-31'), 302)
    assert cc_transaction._signature is None
    return cc_transaction
