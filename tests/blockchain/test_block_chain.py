from datetime import datetime, date

import Crypto
import pytest
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from src.blockchain import utils
from src.blockchain.block_chain import RewardTransaction, Transaction, TransactionError, Block, BlockChain, \
    TransactionPool, TransactionEncoder


class TestTransaction:
    def test_is_reward_transaction(self, client_1, client_2):
        rt = RewardTransaction(client_1, client_2.publickey(), 10)
        assert rt.is_reward()

    def test_is_not_reward_transaction(self, client_1, client_2):
        rt = Transaction(client_1, client_2.publickey(), 10)
        assert not rt.is_reward()

    def test_create_reward_transaction(self, client_1, client_2):
        rt = Transaction.create_reward_transaction(client_1, client_2.publickey(), 10)
        assert rt.is_reward()

    def test_calculate_hash(self, client_1, client_2):
        t = Transaction(client_1, client_2.publickey(), 10)
        assert t.calculate_hash().hexdigest() is not None

    def test_sign_transaction(self, client_1, client_2):
        t = Transaction(client_1.publickey(), client_2.publickey(), 10)
        t.sign_transaction(client_1)
        assert t.get_signature() is not None

    def test_not_sign_transaction(self, client_1, client_2):
        t = Transaction(client_1, client_2.publickey(), 10)
        with pytest.raises(Exception) as exc_info:
            t.sign_transaction(client_2)
            assert str(exc_info.value) == "Attempt to sign transaction with another wallet"
        assert issubclass(exc_info.type, (TransactionError))

    def test_is_valid(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        assert block_chain.is_chain_valid()

    def test_is_not_valid_since_it_is_tampered(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        # look for a non RewardTransaction
        last_block = block_chain.get_chain_of_blocks()[-1]
        last_transaction = last_block.get_transactions()[-1]
        assert not last_transaction.is_reward()
        # tamper the transaction
        last_transaction._amount = 1000
        assert not block_chain.is_chain_valid()

    def test_is_not_valid_since_no_from_wallet(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        # look for a non RewardTransaction
        last_block = block_chain.get_chain_of_blocks()[-1]
        last_transaction = last_block.get_transactions()[-1]
        assert not last_transaction.is_reward()
        # tamper the transaction
        last_transaction._from_address = None
        assert not block_chain.is_chain_valid()

    def test_is_not_valid_since_with_no_signature(self, client_1, client_2):
        t = RewardTransaction(client_1.publickey(), client_2.publickey(), 10)
        t.sign_transaction(client_1)
        t._signature = None
        assert not t.is_valid()

    def test_to_dict(self, client_1, client_2):
        t = Transaction(client_1.publickey(), client_2.publickey(), 10)
        t.sign_transaction(client_1)
        assert Transaction.is_valid_dict(t.to_dict())

    def test_is_not_valid_dict(self, client_1, client_2):
        t = Transaction(client_1.publickey(), client_2.publickey(), 10)
        t.sign_transaction(client_1)
        d = t.to_dict()
        del d["signature"]
        with pytest.raises(Exception) as exc_info:
            assert Transaction.is_valid_dict(d)

    def test_is_reward(self, client_1, client_2):
        t = Transaction(client_1, client_2.publickey(), 10)
        assert not t.is_reward()


class TestTransactionEncoder:
    # noinspection PyTypeChecker
    def test_encode_decode(self, client_1, client_2):
        t = Transaction(client_1.publickey(), client_2.publickey(), 10)
        t.sign_transaction(client_1)
        to_dict = TransactionEncoder.default(None, t)
        from_dict = TransactionEncoder.decode_dict(to_dict)
        assert t == from_dict


class TestTransactionPool:

    def test_append_reward_transaction(self, client_1, client_2):
        tp = TransactionPool()
        tp.append(RewardTransaction(client_1, client_2.publickey(), 10))
        assert tp.size() == 1

    def test_append_cc_transaction(self, cc_transaction):
        tp = TransactionPool()
        tp.append(cc_transaction)
        assert tp.size() == 1

    def test_append_transaction(self, client_1, client_2):
        tp = TransactionPool()
        tp.append(Transaction(client_1, client_2.publickey(), 10))
        assert tp.size() == 1

    def test_is_empty(self, client_1, client_2):
        tp = TransactionPool()
        tp.append(RewardTransaction(client_1, client_2.publickey(), 10))
        assert not tp.is_empty()

    def test_slice(self, client_1, client_2):
        tp = TransactionPool()
        for i in range(1, 5):
            tp.append(RewardTransaction(client_1, client_2.publickey(), 10))
        sliced = tp.slice(3)
        assert (len(sliced) == 3)

    def test_get_pending_transactions(self, block_chain_with_ready_to_mine_block):
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        assert block_chain.get_pool_transactions().size() == 2

    def test_to_dict(self, block_chain_with_ready_to_mine_block):
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        all_elements = [pending.to_dict() for pending in
                        block_chain.get_pool_transactions()._get_pending_transactions()]
        assert all_elements == block_chain.get_pool_transactions().to_dict()

    def test_is_there_transaction_pending_for(self, block_chain_with_ready_to_mine_block):
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        client_1 = block_chain_with_ready_to_mine_block["client_1"]
        assert block_chain.get_pool_transactions().is_there_transaction_pending_for(client_1.publickey())

    def test_is_there_transaction_pending_for_1(self, block_chain_with_ready_to_mine_block):
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        random = Crypto.Random.new().read
        client = RSA.generate(1024, random)
        assert not block_chain.get_pool_transactions().is_there_transaction_pending_for(client.publickey())


class TestBlock:
    def test_to_dict(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        dict = block_chain.get_chain_of_blocks()[0].to_dict()
        assert int(dict["nonce"]) >= 0
        # just parse and let's fail if any
        datetime.strptime(dict["timestamp"], '%Y-%m-%d')
        assert dict["previous_hash"] is not None
        assert dict["hash"] is not None
        assert all([Transaction.is_valid_dict(t) for t in dict["transactions"]])

    def test_is_valid_dict(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        dict = block_chain.get_chain_of_blocks()[0].to_dict()
        del dict["previous_hash"]
        assert not Block.is_valid_dict(dict)

    def test_calculate_hash(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[0]
        assert block.calculate_hash().hexdigest() is not None

    def test_proof_work(self, client_1, client_2):
        difficulty = 3
        transaction = Transaction(client_1.publickey(), client_2.publickey(), 10)
        transaction.sign_transaction(client_1)
        block = Block(datetime.now(), [transaction], None)
        block.proof_work(difficulty)
        assert (block.get_hash().hexdigest()[0:difficulty]) == "".zfill(difficulty)

    def test_valid_reward_transaction(self, block_chain_with_mined_blocks, client_1, client_2):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[0]
        transaction = RewardTransaction(client_1.publickey(), client_2.publickey(), 10)
        transaction.sign_transaction(client_1)
        assert block.is_valid_reward_transaction(transaction)
        transaction = Transaction(client_1.publickey(), client_2.publickey(), 10)
        transaction.sign_transaction(client_1)
        assert not block.is_valid_reward_transaction(transaction)

    def test_not_valid_reward_transaction(self, block_chain_with_mined_blocks, client_1, client_2):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        #
        transaction = RewardTransaction(client_1.publickey(), client_2.publickey(), 10)
        transaction.sign_transaction(client_1)
        block_chain.add_to_pending_transactions(transaction)
        block_chain.mine_pending_transactions(True)
        #
        block = block_chain.get_chain_of_blocks()[-1]
        assert block.has_valid_transactions()
        #
        transaction._amount = transaction._amount + 1
        assert not block.is_valid_reward_transaction(transaction)
        assert not block.has_valid_transactions()

    def test_not_valid_reward_transaction_since_not_signed(self, block_chain_with_mined_blocks, client_1, client_2):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[0]
        transaction = Transaction(client_1.publickey(), client_2.publickey(), 10)
        assert not block.is_valid_reward_transaction(transaction)

    def test_valid_cc_transaction(self, block_chain_with_mined_blocks, client_cc, cc_transaction):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[0]
        cc_transaction.sign_transaction(client_cc)
        assert block.is_valid_cc_transaction(cc_transaction)

    def test_not_valid_cc_transaction(self, block_chain_with_mined_blocks, client_1, client_2, cc_transaction):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[0]
        cc_transaction.set_data("John Doe", "1234", None, None)  # missing data should not be valid
        assert not block.is_valid_cc_transaction(cc_transaction)

    def test_has_valid_transactions(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[-1]
        assert block.has_valid_transactions()

    def test_has_valid_transactions_1(self, invalid_transaction_in_block):
        assert not invalid_transaction_in_block.has_valid_transactions()

    def test_to_json(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[-1]
        js = Block.to_json_string(block)
        restored = Block.from_json_string(js)
        assert block.assert_is_same(restored)

    def test_block_not_equal(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block = block_chain.get_chain_of_blocks()[-1]
        js = Block.to_json_string(block)
        other = Block(block.get_timestamp(),
                      [TransactionEncoder.decode_dict(TransactionEncoder.default(None, t)) for t in
                       block.get_transactions()], block.get_previous_hash(), block.get_nonce(), block.get_hash())
        assert block == other
        other.get_transactions()[-1]._amount = other.get_transactions()[-1]._amount + 1
        assert block != other


class TestBlockChain:
    def test_to_dict(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        dict = block_chain.to_dict()
        assert utils.deserialize(dict["reward_key"]) == block_chain.get_reward_key()
        assert utils.deserialize(dict["mining_address"]) == block_chain.get_mining_address()
        assert dict["difficulty"] == block_chain.get_difficulty()
        assert dict["mining_reward_amount"] == block_chain.get_mining_reward_amount()
        assert len(dict["pool_transactions"]) == 0
        assert len(dict["chain"]) > 0
        assert all([Block.is_valid_dict(b) for b in dict["chain"]])
        assert Transaction.is_valid_dict(dict["genesis_transaction"])

    def test_add_block(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        #
        transaction = Transaction(client_1.publickey(), client_2.publickey(), 10)
        transaction.sign_transaction(client_1)
        #
        previous_size = block_chain.chain_size()
        block = Block(datetime.now(), [transaction], None)
        block.proof_work(block_chain.get_difficulty())
        block_chain.add_block(block)
        assert block_chain.chain_size() == previous_size + 1

    def test_add_block_reject_since_not_proofed(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        #
        transaction = Transaction(client_1.publickey(), client_2.publickey(), 10)
        transaction.sign_transaction(client_1)
        #
        previous_size = block_chain.chain_size()
        block = Block(datetime.now(), [transaction], None)
        with pytest.raises(Exception) as exc_info:
            block_chain.add_block(block)
        # add is rejected (not added to the transactions) since the block is not proofed
        assert block_chain.chain_size() == previous_size

    def test_load_from_store(self):
        block_chain = BlockChain.load_from_store(10)
        assert block_chain is not None

    def test_create_genesis_block(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        genesis_block = block_chain.create_genesis_block()
        assert genesis_block.get_timestamp() == date.fromisoformat('2022-03-27')
        assert len(genesis_block.get_transactions()) == 1
        assert genesis_block.get_hash().hexdigest() == block_chain.create_genesis_block().get_hash().hexdigest()

    def test_add_transaction_no_source(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        with pytest.raises(Exception) as exc_info:
            transaction = Transaction(None, client_1.publickey(), 10)
        assert str(exc_info.value) == "Need a from wallet"

    def test_add_transaction_no_target(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        transaction = Transaction(client_1.publickey(), None, 10)
        with pytest.raises(Exception) as exc_info:
            block_chain.add_to_pending_transactions(transaction)
            assert str(exc_info.value) == "Cannot add transaction : no source or target wallet"
        assert issubclass(exc_info.type, (TransactionError))

    def test_add_transaction_with_invalid_transaction(self, block_chain_with_mined_blocks,
                                                      invalid_transaction_in_block):
        transaction = invalid_transaction_in_block.get_transactions()[-1]
        block_chain = block_chain_with_mined_blocks["blockchain"]
        with pytest.raises(Exception) as exc_info:
            block_chain.add_to_pending_transactions(transaction)
            assert str(exc_info.value) == "Cannot add transaction : invalid transaction"
        assert issubclass(exc_info.type, (TransactionError))

    def test_add_transaction_with_invalid_amount(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        transaction = Transaction(client_1.publickey(), client_2, -1)
        with pytest.raises(Exception) as exc_info:
            block_chain.add_to_pending_transactions(transaction)
            assert str(exc_info.value) == "Cannot add transaction : negative amount"
        assert issubclass(exc_info.type, (TransactionError))

    def test_add_transaction_with_transaction_in_progress(self, block_chain_with_ready_to_mine_block):
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        client_1 = block_chain_with_ready_to_mine_block["client_1"]
        client_2 = block_chain_with_ready_to_mine_block["client_2"]
        transaction = Transaction(client_1.publickey(), client_2, 10)
        with pytest.raises(Exception) as exc_info:
            block_chain.add_to_pending_transactions(transaction)
            assert str(exc_info.value) == "Cannot add transaction : Transaction in progress"
        assert issubclass(exc_info.type, (TransactionError))

    def test_add_transaction_with_not_enough_balance(self, block_chain_with_ready_to_mine_block):
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        client_1 = block_chain_with_ready_to_mine_block["client_1"]
        client_2 = block_chain_with_ready_to_mine_block["client_2"]
        transaction = Transaction(client_1.publickey(), client_2.publickey(), 1000000)
        with pytest.raises(Exception) as exc_info:
            block_chain.add_to_pending_transactions(transaction)
            assert str(exc_info.value) == "Cannot add transaction : Transaction in progress"
        assert issubclass(exc_info.type, (TransactionError))

    def test_choose_transactions(self, block_chain_with_ready_to_mine_block):
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        assert block_chain.get_pool_transactions().size() == 2
        transactions = block_chain.choose_transactions(True)
        assert len(transactions) == 2

    def test_mine_pending_transactions(self, block_chain_with_ready_to_mine_block):
        random = Crypto.Random.new().read
        miner_private_key = RSA.generate(1024, random)
        block_chain = block_chain_with_ready_to_mine_block["blockchain"]
        block_chain.setOwner(miner_private_key)
        block_chain.mine_pending_transactions(True)
        assert block_chain.get_pool_transactions().size() == 0

    def test_get_balances(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        miner = block_chain_with_mined_blocks["miner"]
        balances = block_chain.get_balances()
        assert balances[utils.serialize(client_1.publickey())] == 80
        assert balances[utils.serialize(client_2.publickey())] == 70
        assert balances[utils.serialize(miner.publickey())] == 10

    def test_get_balance_for_address(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]

        #
        tx = Transaction(client_1.publickey(), client_2.publickey(), 5)
        tx.sign_transaction(client_1)
        block_chain.add_to_pending_transactions(tx)
        tx2 = Transaction(client_2.publickey(), client_1.publickey(), 1)
        tx2.sign_transaction(client_2)
        block_chain.add_to_pending_transactions(tx2)
        #
        random = Crypto.Random.new().read
        miner_private_key = RSA.generate(1024, random)
        block_chain.setOwner(miner_private_key)
        #
        block_chain.mine_pending_transactions(True)
        #
        assert block_chain.get_balance_for_address(client_1.publickey()) == 76  # 80 - 5 + 1
        assert block_chain.get_balance_for_address(client_2.publickey()) == 74  # 70 + 5 - 1
        assert block_chain.get_balance_for_address(miner_private_key.publickey()) == 10  # for the current mining

    def test_not_valid_since_no_owner(self, block_chain_without_owner):
        with pytest.raises(Exception):
            block_chain_without_owner.create_reward_transaction(None)

    def test_is_chain_valid(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        genesis_block = block_chain.get_chain_of_blocks()[0]
        genesis_block._timestamp = date.fromisoformat('1970-03-27')
        assert not block_chain.is_chain_valid()

    def test_add_with_negative_amount(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        t = Transaction(client_1.publickey(), client_2.publickey(), -1)
        t.sign_transaction(client_1)
        with pytest.raises(TransactionError) as exc_info:
            block_chain.add_to_pending_transactions(t)
        assert str(exc_info.value) == "Cannot add transaction : negative amount"

    def test_add_with_same_wallets(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        t = Transaction(client_1.publickey(), client_1.publickey(), 10000000)
        t.sign_transaction(client_1)
        with pytest.raises(TransactionError) as exc_info:
            block_chain.add_to_pending_transactions(t)
        assert str(exc_info.value) == 'Cannot add transaction : invalid transaction'

    def test_add_with_not_enough_balance(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        t = Transaction(client_1.publickey(), client_2.publickey(), 10000000)
        t.sign_transaction(client_1)
        with pytest.raises(TransactionError) as exc_info:
            block_chain.add_to_pending_transactions(t)
        assert str(
            exc_info.value) == 'Cannot add transaction : Not enough balance. required 10000000 while account is 80'

    def test_add_with_transaction_in_progress(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        t = Transaction(client_1.publickey(), client_2.publickey(), 1)
        t.sign_transaction(client_1)
        block_chain.add_to_pending_transactions(t)
        t2 = Transaction(client_1.publickey(), client_2.publickey(), 1)
        t2.sign_transaction(client_1)
        with pytest.raises(TransactionError) as exc_info:
            block_chain.add_to_pending_transactions(t2)
        assert str(exc_info.value) == "Cannot add transaction : Transaction in progress"

    def test_to_json_string(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        block_chain.setOwner(None)  # set to None since the BlockChain.from_json_string() is expected to not set it
        js = BlockChain.to_json_string(block_chain)
        restored = BlockChain.from_json_string(js)
        assert block_chain == restored

    def test_block_not_proofed(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        t = Transaction(client_1.publickey(), client_2.publickey(), 1)
        t.sign_transaction(client_1)
        block = Block(datetime.now(), [t], block_chain._chain[-1].get_hash())
        block_chain._chain.append(block)
        assert not block_chain.is_chain_valid()

    def test_block_invalid_hash(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        hash_object: Crypto.Hash.SHA256.SHA256Hash = SHA256.new()
        hash_object.update("test".encode('utf-8'))
        block_chain._chain[-1]._hash = hash_object
        assert not block_chain.is_chain_valid()

    def test_block_invalid_previous_hash(self, block_chain_with_mined_blocks):
        block_chain = block_chain_with_mined_blocks["blockchain"]
        client_1 = block_chain_with_mined_blocks["client_1"]
        client_2 = block_chain_with_mined_blocks["client_2"]
        hash_object: Crypto.Hash.SHA256.SHA256Hash = SHA256.new()
        hash_object.update("test".encode('utf-8'))
        block_chain._chain[-1]._previous_hash = hash_object
        assert not block_chain.is_chain_valid()
