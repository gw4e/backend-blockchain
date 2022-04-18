import logging
from typing import Any, Dict

import Crypto
from Crypto.PublicKey import RSA

from src.blockchain import utils
from src.blockchain.block_chain import BlockChain, Transaction, CreditCardTransaction


class Api:
    def __init__(self, block_chain: BlockChain):
        self._blockchain = block_chain

    def add_cc_transaction(self, from_wallet, to_wallet, from_wallet_private_key, amount,
                           credit_card_cc_number,
                           credit_card_cc_date,
                           credit_card_cc_pict,
                           credit_card_cc_name,
                           id=None) -> Transaction:
        transaction = CreditCardTransaction(from_wallet, to_wallet, amount, id)
        transaction.set_data(credit_card_cc_name, credit_card_cc_number, credit_card_cc_date, credit_card_cc_pict)
        logging.info(f'add_cc_transaction {transaction.get_uuid()} with amount {transaction.get_amount()}')
        transaction.sign_transaction(from_wallet_private_key)
        self._blockchain.add_to_pending_transactions(transaction)
        return transaction

    def add_transaction(self, from_wallet, to_wallet, from_wallet_private_key, amount, id=None) -> Transaction:
        transaction = Transaction(from_wallet,
                                  to_wallet,
                                  amount, id)
        logging.info(f'add_transaction {transaction.get_uuid()} with amount {transaction.get_amount()}')
        transaction.sign_transaction(from_wallet_private_key)
        self._blockchain.add_to_pending_transactions(transaction)
        return transaction

    def describe_blockchain(self) -> str:
        return self._blockchain.to_dict()

    def get_blockchain_id(self) -> str:
        return str(self._blockchain.get_id())

    def get_block_chain_as_json_string(self) -> str:
        return BlockChain.to_json_string(self._blockchain)

    def get_balance_for_address(self, client_public_key) -> int:
        return self._blockchain.get_balance_for_address(client_public_key)

    def get_wallets(self):
        return self._blockchain.get_wallets()

    def create_key(self) -> Dict[str, Any]:
        random = Crypto.Random.new().read
        private_key = RSA.generate(1024, random)
        return {
            "private": utils.serialize(private_key),
            "public": utils.serialize(private_key.publickey())
        }
