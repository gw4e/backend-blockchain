import binascii
import json
import logging
import random
import threading
import uuid
from datetime import datetime, date
from json import JSONEncoder
from pathlib import Path
from typing import List

import Crypto
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from dotenv import load_dotenv

from src.blockchain import utils
from src.config import config


class TransactionError(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class Transaction:
    def __init__(self, from_address, to_address, amount: int, id: uuid.UUID = None, signature: bytes = None,
                 attached_fee: int = 0):
        '''

        :param from_address: Crypto.PublicKey.RSA._RSAobj
        :param to_address: Crypto.PublicKey.RSA._RSAobj
        :param amount: int
        :param id: uuid.UUID
        :param signature: bytes
        '''
        self._uuid = uuid.uuid4() if id is None else id
        self._amount = amount
        self._from_address = from_address
        if from_address is None:
            raise Exception('Need a from wallet')
        self._to_address = to_address
        self._signature = signature
        self._attached_fee = attached_fee

    def get_uuid(self) -> uuid.UUID:
        return self._uuid

    def get_from_address(self):
        '''

        :return: Crypto.PublicKey.RSA._RSAobj
        '''
        return self._from_address

    def get_to_address(self):
        '''

        :return: Crypto.PublicKey.RSA._RSAobj
        '''
        return self._to_address

    def get_signature(self) -> bytes:
        return self._signature

    def get_amount(self) -> int:
        return self._amount

    def get_attached_fee(self) -> int:
        return self._attached_fee

    def __eq__(self, other) -> bool:
        return self._amount == other._amount and self._from_address == other._from_address \
               and self._to_address == other._to_address and self._signature == other._signature \
               and self._uuid == other._uuid

    def __repr__(self) -> str:
        return json.dumps(self, default=lambda o: str(self._amount) + " " + str(
            self._uuid) + " " + "None" if self._from_address is None else utils.serialize(
            self._from_address) + " " + utils.serialize(self._to_address), sort_keys=True,
                          indent=4)

    def create_reward_transaction(from_address, mining_reward_address, mining_reward_amount: int):
        '''

        :param mining_reward_address: Crypto.PublicKey.RSA._RSAobj
        :param mining_reward_amount: Crypto.PublicKey.RSA._RSAobj
        :return:
        '''
        return RewardTransaction(from_address, mining_reward_address, mining_reward_amount)

    def calculate_hash(self) -> Crypto.Hash.SHA256.SHA256Hash:
        hash_object: Crypto.Hash.SHA256.SHA256Hash = SHA256.new()
        # data = str(self._from_address) + str(self._to_address) + str(self._amount) + str(self._uuid)
        data = utils.serialize(self._from_address) + utils.serialize(self._to_address) + str(self._amount) + str(
            self._uuid)
        hash_object.update(data.encode('utf-8'))
        return hash_object

    def sign_transaction(self, signing_private_key):
        """
        Sign the transaction
        :param signing_private_key: Crypto.PublicKey.RSA._RSAobj
        :return: the signed hash string
        """
        if signing_private_key.publickey() != self._from_address:
            raise TransactionError("Attempt to sign transaction with another wallet")
        signer = PKCS1_v1_5.new(signing_private_key)
        self._signature = signer.sign(self.calculate_hash())

    def is_valid(self) -> bool:
        if self._from_address is not None and self._to_address is not None and self._from_address == self._to_address:
            logging.info("From and To wallets are identicals")
            return False
        if self.is_reward():
            if self._signature is None or len(self._signature) == 0:
                logging.info("Reward or Credit Card Transaction invalid : signature failed")
                return False
            verifier = PKCS1_v1_5.new(self._from_address)
            verified = verifier.verify(self.calculate_hash(), self._signature)
            return verified
        if self._signature is None or len(self._signature) == 0:
            logging.info("Transaction invalid : signature failed")
            return False
        if self._from_address is None or (type(self._from_address) == str and len(self._from_address) == 0):
            logging.info("Transaction invalid : from_address failed")
            return False
        verifier = PKCS1_v1_5.new(self._from_address)
        verified = verifier.verify(self.calculate_hash(), self._signature)
        if not verified:
            logging.info("Transaction invalid : verification failed")
        return verified

    def to_dict(self):
        return {
            "uuid": str(self._uuid),
            "amount": self._amount,
            "attached_fee": self._attached_fee,
            "from_address": utils.serialize(self._from_address),
            "to_address": utils.serialize(self._to_address),
            "signature": binascii.hexlify(self._signature).decode('utf-8')
        }

    def is_valid_dict(dict):
        try:
            return dict["uuid"] is not None and dict["amount"] is not None and dict["attached_fee"] is not None and \
                   dict["from_address"] is not None and dict["to_address"] is not None and dict["signature"] is not None
        except KeyError as err:
            return False

    def is_reward(self):
        return False

    def is_credit_card(self):
        return False

    def is_std(self):
        return True


class RewardTransaction(Transaction):
    def __init__(self, from_address, to_address, amount: int, id: uuid.UUID = uuid.uuid4(), signature: bytes = None):
        super().__init__(from_address, to_address, amount, id, signature)

    def is_reward(self):
        return True

    def is_credit_card(self):
        return False

    def is_std(self):
        return True


class CreditCardTransaction(Transaction):
    def __init__(self, from_address, to_address, amount: int, id: uuid.UUID = uuid.uuid4(), signature: bytes = None):
        super().__init__(from_address, to_address, amount, id, signature)
        self._cc_number = None
        self._cc_date = None
        self._cc_pict = None

    def is_reward(self):
        return False

    def is_credit_card(self):
        return True

    def is_std(self):
        return False

    def is_valid(self) -> bool:
        if self._cc_number is None or self._cc_date is None or self._cc_pict is None or self._cc_name is None:
            return False
        if self._signature is None:
            return False
        # credit card transaction is someone using its cc to buy crypto money
        # we impose that wallet source and target are the same
        if utils.serialize(self._from_address) != utils.serialize(self._to_address):
            return False
        if self._signature is None or len(self._signature) == 0:
            logging.info("Reward or Credit Card Transaction invalid : signature failed")
            return False
        verifier = PKCS1_v1_5.new(self._from_address)
        verified = verifier.verify(self.calculate_hash(), self._signature)
        if not verified:
            return False
        # We should now validate the transaction thru a Credit Card Service
        return True

    def set_data(self, cc_name, cc_number, cc_date, cc_pict):
        self._cc_number = cc_number
        self._cc_name = cc_name
        self._cc_date = cc_date
        self._cc_pict = cc_pict

    def get_cc_number(self):
        return self._cc_number

    def get_cc_date(self):
        return self._cc_date

    def get_cc_pict(self):
        return self._cc_pict

    def get_cc_name(self):
        return self._cc_name

    def calculate_hash(self) -> Crypto.Hash.SHA256.SHA256Hash:
        hash_object: Crypto.Hash.SHA256.SHA256Hash = SHA256.new()
        data = utils.serialize(self._from_address) + utils.serialize(self._to_address) + str(self._amount) + str(
            self._uuid) + str(self._cc_number) + self.get_cc_date().isoformat() + str(self._cc_pict) + str(
            self._cc_name)
        hash_object.update(data.encode('utf-8'))
        return hash_object


class TransactionEncoder(JSONEncoder):
    def default(self, transaction: Transaction):
        return {
            "amount": str(transaction.get_amount()),
            "attached_fee": str(transaction.get_attached_fee()),
            "uuid": str(transaction.get_uuid()),
            "from_address": None if transaction.get_from_address() is None else utils.serialize(
                transaction.get_from_address()),
            "to_address": utils.serialize(transaction.get_to_address()),
            "signature": binascii.hexlify(transaction.get_signature()).decode('utf-8'),
            "reward": transaction.is_reward(),
            "credit_card": transaction.is_credit_card(),
            "credit_card_cc_number": transaction.get_cc_number() if transaction.is_credit_card() else "",
            "credit_card_cc_date": transaction.get_cc_date().isoformat() if transaction.is_credit_card() else "",
            "credit_card_cc_pict": transaction.get_cc_pict() if transaction.is_credit_card() else "",
            "credit_card_cc_name": transaction.get_cc_name() if transaction.is_credit_card() else ""
        }

    def decode_dict(obj):
        from_address = None if obj["from_address"] is None else utils.deserialize(obj["from_address"])
        to_address = utils.deserialize(obj["to_address"])
        amount = int(obj["amount"])
        attached_fee = int(obj["attached_fee"])
        id = uuid.UUID(str(obj["uuid"]))
        signature = binascii.unhexlify(obj["signature"])
        reward = obj["reward"]
        credit_card = obj["credit_card"]
        if reward:
            return RewardTransaction(from_address, to_address, amount, id, signature)
        elif credit_card:
            cc = CreditCardTransaction(from_address, to_address, amount, id, signature)
            card_number = obj["credit_card_cc_number"]
            card_date = datetime.fromisoformat(obj["credit_card_cc_date"])
            card_pict = obj["credit_card_cc_pict"]
            card_name = obj["credit_card_cc_name"]
            cc.set_data(card_name, card_number, card_date, card_pict)
            return cc
        else:
            return Transaction(from_address, to_address, amount, id, signature, attached_fee)

    # def decode_json(self, obj: str):
    #    obj = json.loads(obj)
    #    return TransactionEncoder.decode_dict(obj)

    def decode(self, obj):
        #    if type(obj) is str:
        #        return self.decode_json(obj)
        #    else:
        return TransactionEncoder.decode_dict(obj)


class TransactionPool:
    def __init__(self):
        self._pending_transactions: List[Transaction] = []

    def __eq__(self, other) -> bool:
        return self._pending_transactions == other._pending_transactions

    def append(self, transaction: Transaction):
        if isinstance(transaction, Transaction):
            self._pending_transactions.append(transaction)

    def size(self) -> int:
        return len(self._pending_transactions)

    def is_empty(self) -> int:
        return self.size() == 0

    def slice(self, size: int) -> List[Transaction]:
        elements = self._pending_transactions[:size]
        self._pending_transactions = self._pending_transactions[size:]
        return elements

    def _get_pending_transactions(self) -> List[Transaction]:
        return self._pending_transactions

    def to_dict(self):
        return [transaction.to_dict() for transaction in self._pending_transactions]

    def is_there_transaction_pending_for(self, from_address) -> bool:
        return len([t for t in self._pending_transactions if
                    utils.serialize(t.get_from_address()) == utils.serialize(from_address)]) > 0


class TransactionPoolEncoder(JSONEncoder):
    def default(self, pool: TransactionPool):
        return [TransactionEncoder.default(self, t) for t in pool._get_pending_transactions()]


class TransientBlock():
    def __init__(self, timestamp: datetime.date, transactions: List[Transaction], previous_hash: str, hash: str,
                 nonce: int):
        self._nonce: int = nonce
        self._timestamp: datetime.date = timestamp
        self._transactions: List[Transaction] = transactions
        self._previous_hash: str = previous_hash
        self._hash: str = hash

    # def __repr__(self) -> str:
    #    return str(self._get_nonce()) + " " + str(
    #        self._get_timestamp()) + " " + str([TransactionEncoder.default(self, t) for t in
    #                                      self._transactions]) + " " + self._previous_hash + " " + self._hash

    # def __eq__(self, other) -> bool:
    #    return self._nonce == other._nonce and self._timestamp == other._timestamp and \
    #           self._previous_hash == other._previous_hash and self._hash == other._hash and \
    #           self._transactions == other._transactions

    def get_nonce(self) -> int:
        return self._nonce

    def get_timestamp(self) -> datetime.date:
        return self._timestamp

    def get_transactions(self) -> List[Transaction]:
        return self._transactions

    def get_previous_hash(self) -> str:
        return self._previous_hash

    def get_hash(self) -> str:
        return self._hash


class Block():
    def __init__(self, timestamp: datetime.date, transactions: List[Transaction],
                 previous_hash: Crypto.Hash.SHA256.SHA256Hash, nonce: int = 0,
                 h: Crypto.Hash.SHA256.SHA256Hash = None):
        self._nonce: int = nonce
        self._timestamp: datetime.date = timestamp
        self._transactions: List[Transaction] = transactions
        self._previous_hash: Crypto.Hash.SHA256.SHA256Hash = previous_hash
        self._hash: Crypto.Hash.SHA256.SHA256Hash = h if (h is not None) else self.calculate_hash()

    def to_dict(self):
        return {
            "nonce": self._nonce,
            "transactions": [t.to_dict() for t in self._transactions],
            "timestamp": self._timestamp.isoformat(),
            "previous_hash": str(self._previous_hash.digest()),
            "hash": str(self._hash.digest()),
        }

    @staticmethod
    def is_valid_dict(dic):
        try:
            if (dic["nonce"] is not None and dic["timestamp"] is not None and dic["previous_hash"] is not None and
                    dic["hash"] is not None):
                return all([Transaction.is_valid_dict(t) for t in dic["transactions"]]) and len(dic) == 5
        except KeyError:
            return False

    def assert_is_same(self, transient_block: TransientBlock):
        keys = self.__dict__.keys()
        for key in keys:
            if key == '_previous_hash':
                assert str(self.get_previous_hash().digest()) == transient_block.get_previous_hash()
            elif key == '_hash':
                assert str(self.get_hash().digest()) == transient_block.get_hash()
            else:
                assert (self.__dict__[key] == transient_block.__dict__[key])
        return True

    def get_nonce(self) -> int:
        return self._nonce

    def get_timestamp(self) -> datetime.date:
        return self._timestamp

    def get_transactions(self) -> List[Transaction]:
        return self._transactions

    def get_previous_hash(self) -> Crypto.Hash.SHA256.SHA256Hash:
        return self._previous_hash

    def get_hash(self) -> Crypto.Hash.SHA256.SHA256Hash:
        return self._hash

    def __eq__(self, other) -> bool:
        """

        :param other: Block
        :return: bool
        """
        if self._timestamp != other._timestamp or len(self._transactions) != len(other._transactions) or \
                self._previous_hash.hexdigest() != other._previous_hash.hexdigest() or \
                self._hash.hexdigest() != other._hash.hexdigest():
            return False
        for index in range(0, len(self._transactions)):
            if self._transactions[index] != other._transactions[index]:
                return False
        return True

    def calculate_hash(self) -> Crypto.Hash.SHA256.SHA256Hash:
        hash_object = SHA256.new()
        data = str(self._timestamp) + str(self._transactions) + str(self._nonce)
        hash_object.update(data.encode('utf-8'))
        return hash_object

    def proof_work(self, difficulty: int):
        self._nonce = 1
        self._hash = self.calculate_hash()
        while (self._hash.hexdigest()[0:difficulty]) != "".zfill(difficulty):
            self._nonce += 1
            self._hash = self.calculate_hash()
        # print(f"Mining done with {self._nonce} iteration(s) to produce : {self._hash.hexdigest()}")

    def is_valid_reward_transaction(self, transaction: RewardTransaction) -> bool:
        if not isinstance(transaction, RewardTransaction):
            logging.info("Block invalid : isinstance failed")
            return False
        if not transaction.is_valid():
            logging.info("Block invalid : is_valid failed")
            return False
        # should implement a kind of control of the amount based on
        # amount's transactions in the block or fixed amount
        return True

    def is_valid_cc_transaction(self, transaction: CreditCardTransaction) -> bool:
        if not isinstance(transaction, CreditCardTransaction):
            logging.info("Block invalid : isinstance failed")
            return False
        if not transaction.is_valid():
            logging.info("Block invalid : is_valid failed")
            return False
        return True

    def has_valid_transactions(self) -> bool:
        for transaction in self._transactions:
            if transaction.is_reward():
                if not self.is_valid_reward_transaction(transaction):
                    logging.info("Block invalid : is_valid_reward_transaction failed")
                    return False
            elif transaction.is_credit_card():
                if not self.is_valid_cc_transaction(transaction):
                    logging.info("Block invalid : is_valid_cc_transaction failed")
                    return False
            elif not transaction.is_valid():
                logging.info("Block invalid : transaction failed")
                return False
        return True

    @staticmethod
    def to_json_string(blocks) -> str:
        """

        :param blocks: List[Block] or Block
        :return: str (json format)
        """
        return json.dumps(blocks, indent=4, cls=BlockEncoder)

    @staticmethod
    def from_json_string(blocks_transient_to_json):
        """

        :return: List[TransientBlock] or TransientBlock
        """
        return json.loads(blocks_transient_to_json, cls=TransientBlockEncoder)


class BlockEncoder(JSONEncoder):
    def default_one(self, block):
        return {
            "nonce": block.get_nonce(),
            "timestamp": block.get_timestamp().isoformat(),
            "transactions": [TransactionEncoder.default(self, t) for t in block.get_transactions()],
            "previous_hash": str(block.get_previous_hash().digest()),
            "hash": str(block.get_hash().digest()),
        }

    def default(self, obj):
        ret = []
        if type(obj) is list:
            for item in obj:
                ret.append(self.default_one(item))
            return ret
        else:
            return self.default_one(obj)


class TransientBlockEncoder(JSONEncoder):
    def decode_one(self, obj):
        nonce = int(obj["nonce"])
        timestamp = datetime.fromisoformat(obj["timestamp"])
        transactions = [TransactionEncoder.decode(self, t) for t in obj["transactions"]]
        h = obj["hash"]
        previous_hash = obj["previous_hash"]
        return TransientBlock(timestamp, transactions, previous_hash, h, nonce)

    def decode_all(self, items):
        ret = []
        for item in items:
            ret.append(self.decode_one(item))
        return ret

    def decode(self, obj):
        obj = json.loads(obj)
        ret = []
        if type(obj) is list:
            return self.decode_all(obj)
        else:
            return self.decode_one(obj)


class TransientBlockChain():
    def __init__(self, chain: List[TransientBlock], mining_reward_amount: int, pending_transactions: List[Transaction],
                 id: uuid.UUID, source_blockchain_id: uuid.UUID):
        self._chain: List[TransientBlock] = chain
        self._reward_amount: int = mining_reward_amount
        self._source_blockchain_id: uuid.UUID = source_blockchain_id
        pool = TransactionPool()
        for t in pending_transactions:
            pool.append(t)
        self._pending_transactions: TransactionPool = pool
        self._id: uuid.UUID = id

    def get_id(self) -> uuid.UUID:
        return self._id

    def get_source_blockchain_id(self) -> uuid.UUID:
        return self._source_blockchain_id

    def get_reward_amount(self) -> int:
        return self._reward_amount

    def get_genesis_transaction(self) -> Transaction:
        return self._chain[0].get_transactions()[0]

    def get_genesis_block(self) -> TransientBlock:
        return self._chain[0]

    def get_pending_transactions(self):
        return self._pending_transactions


class BlockChain():
    UPDATED = 'updated'
    NO_UPDATE = 'no update'

    def __init__(self, reward_key, genesis_transaction: Transaction, mining_reward_amount: int, id: uuid.UUID,
                 source_blockchain_id: uuid.UUID = None):
        """

        :param reward_key: Crypto.PublicKey.RSA._RSAobj
        :param genesis_transaction: Transaction
        """
        self._genesis_transaction: Transaction = genesis_transaction
        self._chain: List[Block] = [self.create_genesis_block()]
        self._reward_key = reward_key
        self._lock = threading.Lock()
        self._pool_transactions: TransactionPool = TransactionPool()
        self._mining_address = None
        self._difficulty: int = 2
        self._mining_reward_amount: int = mining_reward_amount
        self._observer = None
        self._id = id
        self._source_blockchain_id = source_blockchain_id if source_blockchain_id is not None else id

    def __eq__(self, other) -> bool:
        """

        :param other: Block
        :return: bool
        """
        return self._genesis_transaction == other._genesis_transaction and self._reward_key == other._reward_key and \
               self._pool_transactions == other._pool_transactions and \
               self._mining_address == other._mining_address and self._difficulty == other._difficulty and \
               self._mining_reward_amount == other._mining_reward_amount and self._chain == other._chain

    def to_dict(self):
        return {
            "genesis_transaction": self._genesis_transaction.to_dict(),
            "chain": [b.to_dict() for b in self._chain],
            "reward_key": utils.serialize(self._reward_key),
            "pool_transactions": self._pool_transactions.to_dict(),
            "mining_address": utils.serialize(self._mining_address),
            "difficulty": self._difficulty,
            "mining_reward_amount": self._mining_reward_amount,
            "id": str(self._id),
            "source_blockchain_id": str(self._source_blockchain_id)
        }

    def chain_size(self) -> int:
        return len(self._chain)

    def is_block_proof_worked(self, block):
        if (block.get_hash().hexdigest()[0:self._difficulty]) != "".zfill(self._difficulty):
            print('a block  not proofed')
            print(block.get_hash().hexdigest())
            return False
        return True

    def add_block(self, block: Block) -> Block:
        if (self.is_block_proof_worked(block)):
            self._chain.append(block)
            return block
        else:
            raise Exception('Block not proofed')

    def get_genesis_block(self) -> Block:
        return self.get_chain_of_blocks()[0]

    def get_genesis_transaction(self) -> Transaction:
        return self._genesis_transaction

    def get_chain_of_blocks(self) -> List[Block]:
        return self._chain

    def get_pool_transactions(self) -> TransactionPool:
        return self._pool_transactions

    def get_difficulty(self) -> int:
        return self._difficulty

    def get_id(self) -> uuid.UUID:
        return self._id

    # when the chain and transaction pool are updated when claiming a consensus
    # this id reppresent the id of the blockchain source (from where come from the data)
    # See update_block_chain_from_consensus method & _get_longest_block_chain method in Network class
    def get_source_blockchain_id(self) -> uuid.UUID:
        return self._source_blockchain_id

    # set at server startup
    def set_identity(self, id):
        self._source_blockchain_id = id
        self._id = id

    def get_mining_reward_amount(self) -> int:
        return self._mining_reward_amount

    def get_mining_address(self):
        return self._mining_address

    def get_reward_key(self):
        """

        :return: Crypto.PublicKey.RSA._RSAobj
        """
        return self._reward_key

    @staticmethod
    def load_from_store(reward_amount) -> 'BlockChain':
        genesis_file_location = config.get_genesis_file_location()
        p = Path.cwd() / "blockchain" / "genesis" if genesis_file_location is None else Path(
            genesis_file_location)
        p = p / "bc.json"
        return BlockChain.from_json_string(p.read_text())

    def setOwner(self, mining_address):
        '''

        :param mining_address: Crypto.PublicKey.RSA._RSAobj
        '''
        self._mining_address = mining_address

    def getOwner(self):
        return self._mining_address

    def _create_genesis_hash(self):
        root_hash_object = SHA256.new()
        data = "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit..."
        root_hash_object.update(data.encode('utf-8'))
        return root_hash_object

    def create_genesis_block(self) -> Block:
        return Block(date.fromisoformat('2022-03-27'), [self._genesis_transaction], self._create_genesis_hash())

    def create_reward_transaction(self, reward_key):
        '''

        :param reward_key: Crypto.PublicKey.RSA._RSAobj
        :return:
        '''
        if (self._mining_address is None):
            raise Exception('BlockChain owner not set')
        tx = Transaction.create_reward_transaction(reward_key.publickey(), self._mining_address.publickey(),
                                                   self._mining_reward_amount)
        tx.sign_transaction(reward_key)
        return tx

    def add_to_pending_transactions(self, transaction):
        with self._lock:
            if not transaction.get_from_address() or not transaction.get_to_address():
                raise TransactionError("Cannot add transaction : no source or target wallet")
            if not transaction.is_valid():
                raise TransactionError("Cannot add transaction : invalid transaction")
            if transaction.get_amount() < 0:
                raise TransactionError('Cannot add transaction : negative amount')
            if self.get_pool_transactions().is_there_transaction_pending_for(transaction.get_from_address()):
                raise TransactionError('Cannot add transaction : Transaction in progress')
            wallet_balance = self.get_balance_for_address(transaction.get_from_address())
            if not transaction.is_reward() and not transaction.is_credit_card() and wallet_balance < transaction.get_amount() + \
                    transaction.get_attached_fee():
                raise TransactionError(
                    f'Cannot add transaction : Not enough balance. required {transaction.get_amount() + transaction.get_attached_fee()} while account is {wallet_balance}')
            self._pool_transactions.append(transaction)

    def choose_transactions(self, all_elements: bool) -> List[Transaction]:
        size = self._pool_transactions.size()
        if size > 0:
            count = size if all_elements else random.randint(0, size - 1)
            return self._pool_transactions.slice(count)
        return []

    def set_observer(self, observer):
        self._observer = observer

    def reset_source(self):
        self._source_blockchain_id = self._id

    def update(self, new_chain: List[Block], new_pool_transactions: TransactionPool, source_blockchain_id: str):
        """

        :param source_blockchain_id: the id of the blockchain from which the data comes from
        :param new_chain: List[Block]
        :param new_pool_transactions: TransactionPool
        """

        logging.info(f"Updating the chain from {source_blockchain_id}")
        logging.info(f"old chain : {len(self._chain)} , new chain : {len(new_chain)}  ")
        logging.info(
            f"old pool size : {self._pool_transactions.size()} , new pool size : {new_pool_transactions.size()}  ")
        logging.info("THREAD INFO")
        logging.info(threading.get_ident())
        # with self._lock:
        self._chain = new_chain
        logging.info(f"Chain updated")
        self._pool_transactions = new_pool_transactions
        logging.info(f"Pool updated")
        self._source_blockchain_id = source_blockchain_id
        logging.info(f"Source updated")
        logging.info(f"Updating the chain from {source_blockchain_id} done")

    def mine_pending_transactions(self, all_elements=False) -> bool:
        with self._lock:
            logging.info("mine_pending_transactions ---> Choose transactions to mine")
            transactions = self.choose_transactions(all_elements)
            logging.info("mine_pending_transactions --->  Choose transactions to mine done")
            transactions.insert(0, self.create_reward_transaction(self._reward_key))
            logging.info("mine_pending_transactions --->  Reward transaction inserted")
            for transaction in transactions:
                logging.info(
                    f"mine_pending_transactions --->  transaction added to block {transaction.get_uuid()} with amount {transaction.get_amount()}")
            block = Block(datetime.now(), transactions, self._chain[-1].get_hash())
            logging.info("mine_pending_transactions --->  Block built")
            block.proof_work(self._difficulty)
            logging.info("mine_pending_transactions --->  Proof work done")
            self.add_block(block)
            logging.info("mine_pending_transactions --->  Block added to the chain")
            if self._observer:
                logging.info("mine_pending_transactions --->  Will update from consensus")
                self._observer.update_from_consensus()
                logging.info("mine_pending_transactions --->  Will update from consensus done")
            else:
                logging.info("mine_pending_transactions --->  Will NOT update from consensus")
            # print(f"Miner Balance : {self.get_balance_for_address(self._mining_address.publickey())}")
        return True

    def get_balances(self):
        all = {}
        for block in self._chain:
            for transaction in block.get_transactions():
                if transaction.get_from_address() is None:
                    all["None"] = None
                else:
                    all[utils.serialize(transaction.get_from_address())] = transaction.get_from_address()
                all[utils.serialize(transaction.get_to_address())] = transaction.get_to_address()
        balances = {}
        for key in all.keys():
            balances[key] = self.get_balance_for_address(all[key])
        return balances

    def get_wallets(self):
        wallets = set()
        for block in self._chain:
            for transaction in block.get_transactions():
                wallets.add(utils.serialize(transaction.get_to_address()))
        return list(wallets)

    def get_balance_for_address(self, address) -> int:
        """

        :param address: Crypto.PublicKey.RSA._RSAobj
        :return: int
        """
        balance = 0
        for block in self._chain:
            for transaction in block.get_transactions():
                if transaction.is_std():
                    if transaction.get_from_address() is not None and address is not None and transaction.get_from_address() == address:
                        balance -= transaction.get_amount()
                    elif address is not None and transaction.get_to_address() == address:
                        balance += transaction.get_amount()
                else:  # CreditCardTransaction
                    if transaction.is_credit_card() and address is not None and transaction.get_to_address() == address:
                        balance += transaction.get_amount()
        return balance

    def is_chain_valid(self) -> bool:
        genesis = self.create_genesis_block()
        if genesis != self._chain[0]:
            logging.info("BlockChain invalid : wrong genesis chain")
            return False
        for index in range(1, len(self._chain)):
            current_block = self._chain[index]
            previous_block = self._chain[index - 1]
            if not current_block.has_valid_transactions():
                logging.info("BlockChain invalid : has_valid_transactions failed")
                return False
            if current_block.get_hash().hexdigest() != current_block.calculate_hash().hexdigest():
                logging.info("BlockChain invalid : current_block hash hexdigest control failed")
                return False
            if current_block.get_previous_hash().hexdigest() != previous_block.get_hash().hexdigest():
                logging.info("BlockChain invalid : current_block previous_hash hexdigest control failed")
                return False
            if not self.is_block_proof_worked(current_block):
                logging.info("BlockChain invalid : is_block_proof_worked failed")
                return False
        return True

    @staticmethod
    def to_json_string(block_chain) -> str:
        """

        :param blocks: List[Block] or Block
        :return: str (json format)
        """
        return json.dumps(block_chain, indent=4, cls=BlockChainEncoder)

    @staticmethod
    def from_json_string(block_chain_to_json):
        """
            This does not reload the woner. It is expected that after this method , one set the owner
                    restored = BlockChain.from_json_string(js)
                    restored.setOwner("... a new owner ...")
        :param block_chain_to_json: serialized blockchain
        :return: BlockChain
        """
        load_dotenv()
        private_reward_key = utils.deserialize(config.get_private_reward_key())
        tbc: TransientBlockChain = json.loads(block_chain_to_json, cls=BlockChainEncoder)
        block_chain = BlockChain(private_reward_key, tbc.get_genesis_transaction(), tbc.get_reward_amount(),
                                 tbc.get_id(), tbc.get_source_blockchain_id())
        block_chain._pool_transactions = tbc.get_pending_transactions()
        previous_block = block_chain.get_genesis_block()
        block_transient: TransientBlock = Block.from_json_string(Block.to_json_string(previous_block))
        # check the file is aligned with the current version of the hashing of the genesis block
        # if not run main.py
        assert block_transient.get_hash() == tbc.get_genesis_block().get_hash()
        assert block_transient.get_previous_hash() == tbc.get_genesis_block().get_previous_hash()
        for index in range(1, len(tbc._chain)):
            try:
                new_block = Block(tbc._chain[index].get_timestamp(),
                                  tbc._chain[index].get_transactions(),
                                  previous_block.get_hash(),
                                  tbc._chain[index].get_nonce())
                assert new_block.assert_is_same(tbc._chain[index])
                previous_block = block_chain.add_block(new_block)
            except Exception as err:
                print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
                print('XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
                print(f'Failed at len {len(tbc._chain)}')
                print(f'Failed at index {index}')
                print(block_chain_to_json)
                raise (err)
        return block_chain


class BlockChainEncoder(JSONEncoder):
    # Rerun the generator (run_generator.sh) when this serialization changes otherwise tests will fail
    # this regenerates the bc.json file. Which is THE genesis blockchain :-)
    def default(self, blockchain: BlockChain):
        return {
            "chain": BlockEncoder.default(BlockEncoder(), blockchain.get_chain_of_blocks()),
            "pool_transactions": TransactionPoolEncoder.default(self, blockchain.get_pool_transactions()),
            "reward_amount": str(blockchain.get_mining_reward_amount()),
            "id": str(blockchain.get_id()),
            "source_blockchain_id": str(blockchain.get_source_blockchain_id())
        }

    def decode(self, obj):
        pool = None
        obj = json.loads(obj)
        chain = TransientBlockEncoder().decode_all(obj["chain"])
        reward_amount = int(obj["reward_amount"])
        id = uuid.UUID(obj["id"])
        source_blockchain_id = uuid.UUID(obj["source_blockchain_id"])
        try:
            pool = [TransactionEncoder.decode(None, t) for t in obj["pool_transactions"]]
        except Exception as err:
            print(err)
        return TransientBlockChain(chain, reward_amount, pool, id, source_blockchain_id)
