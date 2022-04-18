import sys
import uuid
from pathlib import Path

from Crypto.Signature import PKCS1_v1_5
from dotenv import load_dotenv

from src.blockchain import utils
from src.blockchain.block_chain import Transaction, BlockChain
from src.config import config


class GenesisFileGenerator():
    def sign_transaction(self, signing_private_key, h):
        """
        Sign the transaction
        :param signing_private_key: Crypto.PublicKey.RSA._RSAobj
        :return: the signed hash string
        """
        signer = PKCS1_v1_5.new(signing_private_key)
        return signer.sign(h)

    def create_genesis_block_chain(self, amount: int, reward_amount: int):
        """

        :param amount: int
        :return: BlockChain
        """
        load_dotenv()
        private_reward_key = utils.deserialize(config.get_private_reward_key())
        genesis_transaction = Transaction(private_reward_key.publickey(), private_reward_key.publickey(), 0)
        h = genesis_transaction.calculate_hash()
        genesis_transaction._signature = self.sign_transaction(private_reward_key, h)
        return BlockChain(private_reward_key, genesis_transaction, reward_amount, uuid.uuid4())

    def create_persisted_genesis_block_chain(self, p: Path, block_chain):
        json_data = BlockChain.to_json_string(block_chain)
        p.write_text(json_data, 'utf-8')
        return p

    def run(self, p: Path):
        reward_amount = 10
        block_chain = self.create_genesis_block_chain(10000, reward_amount)
        persisted_genesis_block_chain = self.create_persisted_genesis_block_chain(p, block_chain)
        new_bloc_chain: BlockChain = BlockChain.from_json_string(persisted_genesis_block_chain.read_text())
        return {
            "new_bloc_chain": new_bloc_chain,
            "block_chain": block_chain
        }


if __name__ == '__main__':
    input = sys.argv[1]
    genesis_file_location = config.get_genesis_file_location()
    p = Path(input)
    p.mkdir(parents=True, exist_ok=True)
    p = (p / "bc.json")
    generator = GenesisFileGenerator()
    generator.run(p)
