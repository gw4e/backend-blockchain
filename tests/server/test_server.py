import time
from datetime import date

import Crypto
import pytest
import requests
from Crypto.PublicKey import RSA

from src.blockchain import utils
from src.blockchain.block_chain import BlockChain
from src.server.main import app, ServerContainer
from src.server.utils import success_response


@pytest.fixture
def create_block_chain_local():
    def create():
        block_chain = BlockChain.load_from_store(10)
        block_chain.setOwner(None)
        assert len(block_chain.get_chain_of_blocks()) == 1
        return block_chain

    return create


@pytest.fixture(autouse=True)
def create_server_with_mined_blocks(monkeypatch, block_chain_with_mined_blocks):
    def create():
        block_chain = block_chain_with_mined_blocks["blockchain"]
        server = ServerContainer._new_instance(block_chain)
        return server

    return create


@pytest.fixture(autouse=True)
def create_server_without_mined_block(monkeypatch, create_block_chain_local):
    def create():
        #
        block_chain_local = create_block_chain_local()
        server = ServerContainer._new_instance(block_chain_local, False)
        assert server.get_miner().is_running() == False
        return server

    return create


@pytest.fixture()
def test_client():
    app.testing = True
    return app.test_client()


def wait_for_miner_running(server, test_client):
    test_client.post("/status", json={})
    timeout = 5
    timeout_start = time.time()
    while time.time() < timeout_start + timeout:
        try:
            assert server.get_miner().is_running()
            break
        except:
            pass


def test_add_to_pending_transactions(test_client, block_chain_with_mined_blocks):
    block_chain = block_chain_with_mined_blocks["blockchain"]
    client_1 = block_chain_with_mined_blocks["client_1"]
    client_2 = block_chain_with_mined_blocks["client_2"]
    client_1_wallet_value = block_chain.get_balance_for_address(client_1.publickey())
    client_2_wallet_value = block_chain.get_balance_for_address(client_2.publickey())
    payload = {
        "from_address": utils.serialize(client_1.publickey()),
        "to_address": utils.serialize(client_2.publickey()),
        "from_private_key": utils.serialize(client_1),
        "amount": 2
    }
    # the following is needed in order to make sure the blockchain in the server container is the same
    # as the one created by the fixture
    ServerContainer.get_instance(block_chain)
    response = test_client.post("/add_to_pending_transactions", json=payload)
    json = response.json
    assert json["message"] == "Transaction added"


def test_add_cc_transaction_to_pending_transactions(test_client, block_chain_with_mined_blocks):
    block_chain = block_chain_with_mined_blocks["blockchain"]
    random = Crypto.Random.new().read
    client_cc = RSA.generate(1024, random)
    payload = {
        "from_address": utils.serialize(client_cc.publickey()),
        "to_address": utils.serialize(client_cc.publickey()),
        "from_private_key": utils.serialize(client_cc),
        "amount": 123,
        "is_credit_card": True,
        "credit_card_cc_number": "4387729175443174",
        "credit_card_cc_date": date.isoformat(date.fromisoformat('2027-08-31')),
        "credit_card_cc_pict": 302,
        "credit_card_cc_name": "John Doe"
    }
    # the following is needed in order to make sure the blockchain in the server container is the same
    # as the one created by the fixture
    ServerContainer._new_instance(block_chain)
    response = test_client.post("/add_to_pending_transactions", json=payload)
    json = response.json
    assert json["message"] == "Credit Card Transaction added"
    client_cc_wallet_value = block_chain.get_balance_for_address(client_cc.publickey())
    assert client_cc_wallet_value == 0
    block_chain.mine_pending_transactions(True)
    client_cc_wallet_value = block_chain.get_balance_for_address(client_cc.publickey())
    assert client_cc_wallet_value == 123


def test_get_wallets(test_client, block_chain_with_mined_blocks):
    block_chain = block_chain_with_mined_blocks["blockchain"]
    random = Crypto.Random.new().read
    client_cc = RSA.generate(1024, random)
    payload = {
        "from_address": utils.serialize(client_cc.publickey()),
        "to_address": utils.serialize(client_cc.publickey()),
        "from_private_key": utils.serialize(client_cc),
        "amount": 123,
        "is_credit_card": True,
        "credit_card_cc_number": "4387729175443174",
        "credit_card_cc_date": date.isoformat(date.fromisoformat('2027-08-31')),
        "credit_card_cc_pict": 302,
        "credit_card_cc_name": "John Doe"
    }
    # the following is needed in order to make sure the blockchain in the server container is the same
    # as the one created by the fixture
    ServerContainer._new_instance(block_chain)
    response = test_client.post("/add_to_pending_transactions", json=payload)
    block_chain.mine_pending_transactions(True)
    client_cc_wallet_value = block_chain.get_balance_for_address(client_cc.publickey())
    assert client_cc_wallet_value == 123
    response = test_client.get("/get_wallets", json={})
    data = response.json['result']
    index = data.index(utils.serialize(client_cc.publickey()))
    assert index >= 0


def test_describe_blockchain(test_client):
    response = test_client.get("/describe_blockchain", json={})
    json = response.json["result"]

    assert len((json["genesis_transaction"]["uuid"])) > 0
    assert int((json["genesis_transaction"]["amount"])) >= 0
    assert len((json["genesis_transaction"]["from_address"])) > 0
    assert len((json["genesis_transaction"]["to_address"])) > 0
    assert len((json["genesis_transaction"]["signature"])) > 0

    assert len((json["chain"])) > 0
    assert int((json["chain"][0]["nonce"])) == 0
    assert len((json["chain"][0]["timestamp"])) > 0
    assert len((json["chain"][0]["previous_hash"])) > 0
    assert len((json["chain"][0]["hash"])) > 0
    assert len((json["chain"][0]["transactions"])) > 0
    assert len((json["chain"][0]["transactions"][0]["uuid"])) > 0
    assert int((json["chain"][0]["transactions"][0]["amount"])) >= 0
    assert len((json["chain"][0]["transactions"][0]["to_address"])) > 0
    assert len((json["chain"][0]["transactions"][0]["signature"])) > 0

    assert len((json["reward_key"])) > 0
    assert len((json["mining_address"])) > 0
    assert int((json["difficulty"])) > 0
    assert int((json["mining_reward_amount"])) > 0


def test_stop_mining(test_client, create_server_with_mined_blocks, block_chain_with_mined_blocks):
    server = None
    try:
        server = create_server_with_mined_blocks()
        wait_for_miner_running(server, test_client)
        response = test_client.post("/stop_mining", json={})
        timeout = 5  # [seconds]
        timeout_start = time.time()
        while time.time() < timeout_start + timeout and not server.get_miner().is_stopped():
            time.sleep(1)
        assert response.json["message"] == "Miner stopped"
    finally:
        server.get_miner().start()


def test_start_mining(test_client, create_server_with_mined_blocks, block_chain_with_mined_blocks):
    server = None
    try:
        server = create_server_with_mined_blocks()
        server.get_miner().stop()
        timeout = 5  # [seconds]
        timeout_start = time.time()
        while time.time() < timeout_start + timeout and not server.get_miner().is_stopped():
            time.sleep(1)
        assert server.get_miner().is_stopped()
        response = test_client.post("/start_mining", json={})
        assert response.json["message"] == "Miner started"
    finally:
        server.get_miner().start(True)


def test_is_mining(test_client, create_server_with_mined_blocks):
    server = create_server_with_mined_blocks()
    server.get_miner().start(True)
    timeout = 5  # [seconds]
    timeout_start = time.time()
    while time.time() < timeout_start + timeout and not server.get_miner().is_running():
        time.sleep(1)
    response = test_client.get("/is_mining", json={})
    assert response.json["result"]


def test_is_not_mining(test_client, create_server_with_mined_blocks):
    server = None
    try:
        server = create_server_with_mined_blocks()
        wait_for_miner_running(server, test_client)

        response = test_client.post("/stop_mining", json={})
        timeout = 5  # [seconds]
        timeout_start = time.time()
        while time.time() < timeout_start + timeout and not server.get_miner().is_stopped():
            time.sleep(1)
        assert not response.json["result"]
    finally:
        server.get_miner().start()


#
#
def test_register_and_broadcast_nodes(test_client, monkeypatch):
    calls_args = []

    def my_request(method, url, **kwargs):
        calls_args.append({"method": method, "url": url, "dict": kwargs})

    monkeypatch.setattr(requests, 'request', my_request)

    response = test_client.post("/register-and-broadcast-nodes", json={
        "nodeUrl": "http://localhost:3002"
    })
    assert calls_args[0] == {'method': 'POST', 'url': 'http://localhost:3002/register-node',
                             'dict': {'headers': {'Content-Type': 'application/json'},
                                      'data': '{"nodeUrl": "http://localhost:3002"}'}}
    assert response.json["message"] == 'Node added and broadcasted: http://localhost:3002'


#
#
def test_register_node(test_client, monkeypatch):
    response = test_client.post("/register-node", json={
        "nodeUrl": "http://localhost:3002"
    })
    assert response.json["message"] == 'Node registered: http://localhost:3002'


#
#
def test_register_all_nodes(test_client, monkeypatch):
    response = test_client.post("/register-all-nodes", json={
        "network_nodes": ["http://localhost:3001", "http://localhost:3002"]
    })
    assert response.json["message"] == "Nodes all registered: ['http://localhost:3001', 'http://localhost:3002']"


def test_status(test_client):
    response = test_client.get("/status", json={
    })
    result = response.json["result"]
    assert result["status"] == 'started'
    assert result["mining"]


@pytest.mark.parametrize('blocks_length', [[1, 2]])
def test_consensus(test_client, monkeypatch, create_server_without_mined_block, block_chain_with_sized_mined_blocks):
    @app.route('/consensus', methods=['POST'])
    def consensus():
        response = ServerContainer.get_instance().get_network().update_block_chain_from_consensus()
        return success_response(response), 200

    server_without_mined_block = create_server_without_mined_block()
    OTHER_NODES = ["http://localhost:3032", "http://localhost:3033"]
    network = server_without_mined_block.get_network()
    network.register_node(OTHER_NODES[0])
    network.register_node(OTHER_NODES[1])

    response = test_client.post("/status", json={
    })

    #
    def my_request(method, url, **kwargs):
        class RemoteServerFakeResponse():
            def __init__(self):
                self.status_code = 200

            def json(self):
                if method == 'GET' and url == f'{OTHER_NODES[0]}/get_blockchain':
                    return {'result': BlockChain.to_json_string(block_chain_with_sized_mined_blocks[0])}
                elif method == 'GET' and url == f'{OTHER_NODES[1]}/get_blockchain':
                    return {'result': BlockChain.to_json_string(block_chain_with_sized_mined_blocks[1])}
                else:
                    raise Exception('Invalid request')

        return RemoteServerFakeResponse()

    monkeypatch.setattr(requests, 'request', my_request)
    #
    response = test_client.post("/consensus", json={
    })
    result = response.json["result"]
    assert result["status"] == BlockChain.UPDATED
    winner = block_chain_with_sized_mined_blocks[1]
    # assert the blockchain of the server has been updated with the longest blockchain which is block_chain_with_sized_mined_blocks [1]
    assert winner.get_chain_of_blocks() == server_without_mined_block.get_block_chain().get_chain_of_blocks()
    assert winner.get_pool_transactions() == server_without_mined_block.get_block_chain().get_pool_transactions()
