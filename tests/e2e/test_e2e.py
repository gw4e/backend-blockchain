import json
import sys
import time
import uuid
from datetime import date
from pathlib import Path

import pytest
import requests
from xprocess import ProcessStarter

from src.blockchain import utils
from src.blockchain.block_chain import BlockChain
from src.blockchain.network import NetWork

SERVER_CONFIG = [
    {"name": "server_1", "url": "http://localhost:3001", "miner_pause": 10,
     "miner_private_key": "3082025f02010002818100dd94d93c4053e80e56b3b5196cfc819b24990dd50610bc5dd47d4127ae66711335ffd639304e6dcb7283b7b03b1b95671e42a8e7da8c22a5d03ef7caedd8da36b280f7d289fd9e25e1826498ea8e1ba5b99af6eec5e562d508b2b459f524267dcacf7d8bf8c0a5268a18d1f083bb7fa070d5bb480eba98f16ab4fe58935c693f020301000102818100869c94d49ba7ddc4483be87b47d0a6d41f89b3f38439ca959e2f71d3af89a08c3133f96ac8c3fcc3aa100719d2eed0f6d25560d369dbd478b3686d9524a5a6fa8dfdb7887115eec578e5681705b4d86641172ebfa481c0671ad7133c44a3e84d68bd7dae0d96895f22d50077bca91f542a16ceb7e102757781e8adc1d28a1781024100e2a2e92ef44f1f26dd597a68cbdc92d47608a6fba3dbf863fa96d37ab2ea0e2980a63661b10df5d9b25a8df05f162aa9092d20f28e8053d292ed849ab59ff69f024100fa4a468388baba06c5d93413de444a2ee2f5a12abb0beae7ceaee76c05d95b89f8ff4d083b66756504925404e4de5a312cc4706b63d807ebc142affb276fa961024100b1aed1acbb63d0e39284d56095fbdfadecc049d25e1c567863fd9dddc3a996e2d8f6f709ce5b48959dac3b3de9fea20196ad27f8a2da5f5d674e0a39950dcdb7024100eac6ef7c04aebb3f0d29a05b1ebc4a25cf097fa3988f264b4929f1b4f78b9afd424f20d01f000e10b3081bbdf77dc776a73aa1056b43c2b257b79961eaed2821024100d794282d9100ed0916912295c5011fb3563aecee6eb05dba81381ddc0a9c8165128d234d6a4266bce04d63c210219494451dcf2d8e248df950b5063e549d8b19"},
    {"name": "server_2", "url": "http://localhost:3002", "miner_pause": 5,
     "miner_private_key": "3082025e02010002818100de7c84b8cc389708bb91bc187dabcdd2cce9bac3b5305f4ccd4a68737c71892cd4f40e0992c0dfa5e6e260570caa4019b07d220d4e181b6e796dc1fecc9178238d8d7deb50fa01a5050b6e18285ee561cf54d5181a5d0a70ba16269c60bffbf6df243ff33a3043690305d3d720ef727478c52d3f1dcfaac0359b60c2651285ab020301000102818100936d497937022cbac1a7e14f0d3f6204d479f0a32c962020414c94082aa70531eaeec9ba783f4c339fd9d3e2fae679d14c0caf1ac7ebdb8989f73bfc7e4bcaa1ef7e3227b03752127698373c2223f6fca024a703bc89441754578c709ad0f78ed2e0b93c33495b10f00b40d6688df28514031b6f68bd5488a6dfbdee405594a1024100df9a86792705116241f55df63516073b1e0baae67cea0dc4275056db1c8194a706fbc836eb05599192ccb9b12696f6ec580f559534fb2cc20f13b8952fae2731024100feb88e3bcae69221a9f3b6d272e5df856c71641a7f6892a4df399b7a45adc34ac2a66b267ae928ba26cfe6cca7c2dcc4d02aa16bd5aac7232e204d4b5000bb9b024100c274bdf16a8fabb889a7fb18fcbdb57821feff970696fd75d2c2b9663ffa28eec0d20222506d0ca1deca8fca91c6c3e2720a93e0f87c5f463c9a67f1c5cf6c61024100d4760bed43a85e6b45decab76eaede69e3b210d5294088508d00f7f65cf83ad4b8d726b8c9fc80c4046b950f4f3ef1f617cbf72882e81781f88f68e950a9cbd102407452b3d818941f6f878cb5eb72d988c2f9119301ead88ed0f1462cb2f94602d323f0cc6be0f924bb23980731da42873d45d56bb9c7ce1949f29d5d25b4d5f8fb"},
    {"name": "server_3", "url": "http://localhost:3003", "miner_pause": 1,
     "miner_private_key": "3082025c02010002818100b2026aca786ab1f6ac0281d23ab0e41b441bea04a6373991723c759b186b80ce5a25721b564991fbeaefe02381708c454ee60fc2f54d14555b2dd3fc4cbfd1435e94820171670c826ade88eb674daa2edaac63132ccba8926c8b5959e5a432f808ec597c94e7b8e93fa1bd34af2acb8e29f1958b31bbb04f20fc18e88fc66eb702030100010281800105728766d975dbec70b73df5883e46c9c53f3a7799a982e41ce4afd71c06c9284b3eb45972629c076508ec2b39f21413b7ce2f5828f10cec50fefe5b925e28fa54983129c4a30a71f26c5a704dfcfdaeb3689d5f40f2c6304768cb44099cb1b0ebd2ec7d81d7a05fdabeb91525678a0e085351273a2901c4b0a8c6a6b5aa41024100c413103b5adaff660971afecc7c57fb613febe79edb350242130429d8ab454ca3379bd8d151f9063db917e5229ea3d83e4292e66241ce763ba7385a4f099bfdd024100e869f093bb72fd653d6e014242a53dc28492dffb60eb63e97e03359862826efe6fa675980e88bf85be890b41edc588f6237b3a9041d517f26a53d51865c489a30240144ca8f48c2e7a1c9543b8e3f9b6bfc71900d9b583df799f93f40c218557b02392faba9e1d9ebbf32aab4079bf2f2a193a88ecedd4354ddb6c554373d51905dd02406f6da36f60f6cfb08354437c3e31b53b968e489ee027db3e2e3161b7cebb14761e97a357a4d84162e1281962a19a0c815e1f8dc36e1cb99f7b04f86cfb15d09b024100b617e1cbd59d89cc4eb93277039dc9804e41a84fa6b2141b26dfaa7aab37065f9138d93d4ad4c228cbcc94aac3033758ca60259d04ed88a62053a36e8e48d0e5"}
]


def get_winner_blockchain_id():
    pause = float("inf")
    winner_conf = None
    for index in range(0, len(SERVER_CONFIG)):
        url = f"{SERVER_CONFIG[index]['url']}/status"
        response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
        data = response.json()["result"]
        if data['miner_pause'] < pause:
            pause = data['miner_pause']
            winner = SERVER_CONFIG[index]
    assert winner is not None
    url = f"{winner['url']}/describe_blockchain"
    response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
    data = response.json()["result"]
    return uuid.UUID(data["id"])


def directory_find(start):
    for path in start.iterdir():
        if path.is_dir() and path.name == 'src':
            return path.parent
    x = start.parent.absolute()
    return directory_find(x)


@pytest.fixture
def servers(xprocess, configs):
    def create(url, pause, miner_private_key):
        class Starter(ProcessStarter):
            src_path = directory_find(Path.cwd())
            main_path = src_path / "server.py"
            args = [sys.executable, main_path.absolute(), url, pause, True,
                    miner_private_key]  # True stands for app.testing=True
            pattern = "BlockChain Server started"
            # timeout = 5

        return Starter

    for conf in configs:
        xprocess.ensure(conf["name"], create(conf["url"], conf["miner_pause"], conf["miner_private_key"]))

    yield

    for conf in configs:
        xprocess.getinfo(conf["name"]).terminate()


def assert_func_with_timeout(func, timeout):
    timeout_start = time.time()
    while time.time() < timeout_start + timeout:
        try:
            assert func()
            return True
        except:
            time.sleep(1)
            pass
    return False


@pytest.mark.parametrize('configs', [SERVER_CONFIG])
def test_status(servers):
    def func():
        for conf in SERVER_CONFIG:
            url = f"{conf['url']}/status"
            response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
            data = response.json()["result"]
            assert data["mining"]
        return True

    assert assert_func_with_timeout(func, 30)


@pytest.mark.parametrize('configs', [SERVER_CONFIG])
def test_manage_transaction(servers, client_2, client_cc):
    def build_blockchains_network():
        url = f"{SERVER_CONFIG[0]['url']}/register-and-broadcast-nodes"
        response = requests.request("POST", url, headers=NetWork.JSON_HEADER, data=json.dumps({
            "nodeUrl": SERVER_CONFIG[1]['url']
        }))
        data = response.json()["message"]
        assert data == f"Node added and broadcasted: {SERVER_CONFIG[1]['url']}"
        url = f"{SERVER_CONFIG[1]['url']}/register-and-broadcast-nodes"
        #
        response = requests.request("POST", url, headers=NetWork.JSON_HEADER, data=json.dumps({
            "nodeUrl": SERVER_CONFIG[2]['url']
        }))
        data = response.json()["message"]
        assert data == f"Node added and broadcasted: {SERVER_CONFIG[2]['url']}"

    def assert_blockchains_network():
        url = f"{SERVER_CONFIG[0]['url']}/describe_network"
        response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
        data = response.json()["result"]
        assert data["url"] == SERVER_CONFIG[0]['url']
        assert data["other_nodes"] == [SERVER_CONFIG[1]['url'], SERVER_CONFIG[2]['url']]
        #
        url = f"{SERVER_CONFIG[1]['url']}/describe_network"
        response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
        data = response.json()["result"]
        assert data["url"] == SERVER_CONFIG[1]['url']
        assert data["other_nodes"] == [SERVER_CONFIG[0]['url'], SERVER_CONFIG[2]['url']]
        #
        url = f"{SERVER_CONFIG[2]['url']}/describe_network"
        response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
        data = response.json()["result"]
        assert data["url"] == SERVER_CONFIG[2]['url']
        assert data["other_nodes"] == [SERVER_CONFIG[0]['url'], SERVER_CONFIG[1]['url']]

    def keep_mining_to_make_money():
        # check if at least one has enough money
        # we cannot expect to have all nodes blockchain with money, since the faster node will win with its own blockchain
        # and other nodes will always see they reward transactions discarded , since these reward transactions
        # does not exist in the winning chain
        def has_enough_money():  # we almost tend to think they we usually don't :-)
            sum = 0
            for server_config in SERVER_CONFIG:
                server_url = f"{server_config['url']}/balance_for"
                wallet = utils.deserialize(server_config['miner_private_key']).publickey()
                response = requests.request("GET", server_url, headers=NetWork.JSON_HEADER, data=json.dumps({
                    "wallet": utils.serialize(wallet)
                }))
                d = response.json()
                sum = sum + d['result']
            assert sum > 10
            return True

        assert assert_func_with_timeout(has_enough_money, 30)

    def stop_mining():
        def all_stopped():
            for server_config in SERVER_CONFIG:
                server_url = f"{server_config['url']}/is_mining"
                response = requests.request("GET", server_url, headers=NetWork.JSON_HEADER, data={})
                d = response.json()
                assert not d["result"]
            return True

        for server_config in SERVER_CONFIG:
            url = f"{server_config['url']}/stop_mining"
            requests.request("POST", url, headers=NetWork.JSON_HEADER, data={})
        assert assert_func_with_timeout(all_stopped, 30)

    def wait_for_winning_chain_erased_chain_in_other_nodes():
        for conf in SERVER_CONFIG:
            url = f"{conf['url']}/get_blockchain"
            response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
            js = response.json()["result"]
            restored = BlockChain.from_json_string(js)
            expected_winner_blockchain_id = get_winner_blockchain_id()
            assert restored.get_source_blockchain_id() == expected_winner_blockchain_id
        return True

    added_transaction = {
        "transaction": None,
        "cc_transaction": None
    }

    def submit_transaction():
        def wait_for_transaction_to_be_added():
            # Take the private key of the miner, it is the only one having money !
            # He got his money because since the beginning of the test, he mines and get rewards !
            client_1 = utils.deserialize(SERVER_CONFIG[2]['miner_private_key'])
            payload = {
                "from_address": utils.serialize(client_1.publickey()),
                "to_address": utils.serialize(client_2.publickey()),
                "from_private_key": utils.serialize(client_1),
                "amount": 2
            }
            payload_cc = {
                "from_address": utils.serialize(client_cc.publickey()),
                "to_address": utils.serialize(client_cc.publickey()),
                "from_private_key": utils.serialize(client_cc),
                "amount": 500,
                "is_credit_card": True,
                "credit_card_cc_number": "4387729175443174",
                "credit_card_cc_date": date.isoformat(date.fromisoformat('2027-08-31')),
                "credit_card_cc_pict": 302,
                "credit_card_cc_name": "John Doe"
            }
            # send a Transaction to server_1
            server_url = f"{SERVER_CONFIG[2]['url']}/add_to_pending_transactions"
            response = requests.request("POST", server_url, headers=NetWork.JSON_HEADER, data=json.dumps(payload))
            data = response.json()
            assert data["message"] == "Transaction added"
            # send a Credit Card Transaction to server_1
            response = requests.request("POST", server_url, headers=NetWork.JSON_HEADER, data=json.dumps(payload_cc))
            cc_data = response.json()
            assert cc_data["message"] == "Credit Card Transaction added"
            added_transaction.update({"transaction":
                {
                    "transaction_id": data["result"]["transaction_id"],
                    "amount": data["result"]["amount"]
                }
            })
            added_transaction.update({"cc_transaction":
                {
                    "transaction_id": cc_data["result"]["transaction_id"],
                    "amount": cc_data["result"]["amount"]
                }
            })
            return True

        def check_transaction_has_been_broadcasted_to_other_nodes():
            for server_config in SERVER_CONFIG:
                server_url = f"{server_config['url']}/get_blockchain"
                response = requests.request("GET", server_url, headers=NetWork.JSON_HEADER, data={})
                data = json.loads(response.json()["result"])
                transaction = data['pool_transactions'][0]
                assert transaction['amount'] == '2'
            return True

        # need to wait for the next steps of mining so that the client has enough money to make the transaction
        assert assert_func_with_timeout(wait_for_transaction_to_be_added, 30)
        # assert transactions have been broadcasted to other nodes
        # Since the mining is stopped , we are sure that the transactions should be in the transactions pool
        assert assert_func_with_timeout(check_transaction_has_been_broadcasted_to_other_nodes, 30)

    def check_for_added_transaction_in_all_blockchains():
        status = {}
        for server_config in SERVER_CONFIG:
            status.update({server_config['url']: 0})
        expected_transaction = added_transaction["transaction"]
        expected_cc_transaction = added_transaction["cc_transaction"]
        for server_config in SERVER_CONFIG:
            server_url = f"{server_config['url']}/get_blockchain"
            response = requests.request("GET", server_url, headers=NetWork.JSON_HEADER, data={})
            data = json.loads(response.json()["result"])
            chains = data["chain"]
            for chain in chains:
                transactions = chain['transactions']
                for transaction in transactions:
                    if (transaction['uuid'] == expected_transaction['transaction_id'] and int(transaction['amount']) ==
                        expected_transaction['amount']) or \
                            (transaction['uuid'] == expected_cc_transaction['transaction_id'] and int(
                                transaction['amount']) == expected_cc_transaction['amount']):
                        status.update({server_config['url']: status[server_config['url']] + 1})
        assert all(value == 2 for value in status.values())
        return True

    def start_mining():
        def all_started():
            for server_config in SERVER_CONFIG:
                server_url = f"{server_config['url']}/is_mining"
                response = requests.request("GET", server_url, headers=NetWork.JSON_HEADER, data={})
                d = response.json()
                assert d["result"]
            return True

        for server_config in SERVER_CONFIG:
            server_url = f"{server_config['url']}/start_mining"
            requests.request("POST", server_url, headers=NetWork.JSON_HEADER, data={})
        assert assert_func_with_timeout(all_started, 30)

    build_blockchains_network()
    assert_blockchains_network()
    keep_mining_to_make_money()
    assert assert_func_with_timeout(wait_for_winning_chain_erased_chain_in_other_nodes, 60)
    stop_mining()
    submit_transaction()
    start_mining()
    assert assert_func_with_timeout(wait_for_winning_chain_erased_chain_in_other_nodes, 60)
    assert assert_func_with_timeout(check_for_added_transaction_in_all_blockchains, 60)
