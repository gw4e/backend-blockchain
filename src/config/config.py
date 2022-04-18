import os
import sys
from urllib.parse import urlparse

from dotenv import load_dotenv

from src.blockchain import utils

load_dotenv()


def get_genesis_file_location():
    return os.getenv("GENESIS_FILE_LOCATION")


def get_private_reward_key():
    return os.getenv("PRIVATE_REWARD_KEY")


def get_miner_private_key():
    if len(sys.argv) != 5:
        if os.getenv("MINER_PRIVATE_KEY") is not None:
            return utils.deserialize(os.getenv("MINER_PRIVATE_KEY"))
        else:
            raise Exception("Invalid argument. Missing 'miner private key' argument")
    return utils.deserialize(sys.argv[4])


def get_miner_nick_name():
    return os.getenv("MINER_NICK_NAME")


def get_miner_pause_delay():
    if len(sys.argv) != 5:
        if os.getenv("MINER_PAUSE") is not None:
            return int(os.getenv("MINER_PAUSE"))
        else:
            raise Exception("Invalid argument. Missing 'miner pause' argument")
    return int(sys.argv[2])


def get_block_chain_server_url():
    if len(sys.argv) != 5:
        if os.getenv("BLCK_SRV_URL") is not None:
            return os.getenv("BLCK_SRV_URL")
        else:
            raise Exception('Invalid argument. Missing url argument')
    return sys.argv[1]


def get_block_chain_server_port():
    o = urlparse(get_block_chain_server_url())
    try:
        return int(o.port)
    except:
        raise Exception(
            f"Invalid argument. Are you sure the argument passed '{get_block_chain_server_url()}' is a well formatted url ?")
