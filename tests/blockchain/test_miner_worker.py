import time

import Crypto
import pytest
from Crypto.PublicKey import RSA
from dotenv import load_dotenv

from src.blockchain.block_chain import BlockChain
from src.worker.miner_worker import MinerWorker

load_dotenv()


@pytest.fixture
def block_chain():
    block_chain = BlockChain.load_from_store(10)
    random = Crypto.Random.new().read
    block_chain.setOwner(RSA.generate(1024, random))
    return block_chain


@pytest.fixture
def miner(block_chain):
    return MinerWorker(block_chain, "miner_name", 1)


def test_start(miner):
    miner.start()
    timeout = 2  # [seconds]
    timeout_start = time.time()
    while time.time() < timeout_start + timeout:
        try:
            assert miner.is_running()
        except:
            pass
    assert miner.is_running()
    miner.stop()


def test_stop(miner):
    miner.start()
    timeout = 2  # [seconds]
    timeout_start = time.time()
    while time.time() < timeout_start + timeout:
        try:
            assert miner.is_running()
        except:
            pass
    assert miner.is_running()
    miner.stop()
    timeout_start = time.time()
    while time.time() < timeout_start + timeout:
        try:
            assert miner.is_stopped()
        except:
            pass
    assert miner.is_stopped()
