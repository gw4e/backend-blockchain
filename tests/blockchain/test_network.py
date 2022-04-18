import pytest
import requests
from dotenv import load_dotenv

from src.blockchain.block_chain import BlockChain
from src.blockchain.network import NetWork

load_dotenv()


@pytest.fixture
def block_chain() -> BlockChain:
    block_chain = BlockChain.load_from_store(10)
    return block_chain


def test_register_and_broadcast_nodes(monkeypatch, block_chain):
    calls_args = []

    def my_request(method, url, **kwargs):
        calls_args.append({"method": method, "url": url, "dict": kwargs})

    monkeypatch.setattr(requests, 'request', my_request)
    network = NetWork(block_chain, 3001, "http://localhost:3001")
    network.register_and_broadcast_nodes("http://localhost:3002")
    assert calls_args[0] == {'method': 'POST', 'url': 'http://localhost:3002/register-node',
                             'dict': {'headers': {'Content-Type': 'application/json'},
                                      'data': '{"nodeUrl": "http://localhost:3002"}'}}
    assert calls_args[1] == {'method': 'POST', 'url': 'http://localhost:3002/register-all-nodes',
                             'dict': {'headers': {'Content-Type': 'application/json'},
                                      'data': '{"network_nodes": ["http://localhost:3002", "http://localhost:3001"]}'}}
    assert calls_args[2] == {'method': 'POST', 'url': 'http://localhost:3001/register-all-nodes',
                             'dict': {'headers': {'Content-Type': 'application/json'},
                                      'data': '{"network_nodes": ["http://localhost:3002", "http://localhost:3001"]}'}}


def test_register_node(block_chain):
    network = NetWork(block_chain, 3001, "http://localhost:3001")
    network.register_node("http://localhost:3001")
    network.register_node("http://localhost:3002")
    assert network.get_other_nodes_url() == ["http://localhost:3002"]
    network.register_node("http://localhost:3003")
    assert network.get_other_nodes_url() == ["http://localhost:3002", "http://localhost:3003"]


def test_register_all_nodes(block_chain):
    network = NetWork(block_chain, 3001, "http://localhost:3001")
    network.register_all_nodes(["http://localhost:3001", "http://localhost:3002", "http://localhost:3003"])
    assert network.get_other_nodes_url() == ["http://localhost:3002", "http://localhost:3003"]


def test_ask_other_nodes(monkeypatch):
    calls_args = []

    def my_request(method, url, **kwargs):
        calls_args.append({"method": method, "url": url, "dict": kwargs})

    monkeypatch.setattr(requests, 'request', my_request)

    network = NetWork(block_chain, 3001, "http://localhost:3001")
    network.register_all_nodes(["http://localhost:3001", "http://localhost:3002", "http://localhost:3003"])
    network._ask_other_nodes()
    assert len(calls_args) == 2
    assert calls_args[0] == {
        'method': 'GET',
        'url': 'http://localhost:3002/get_blockchain',
        'dict': {'headers': {'Content-Type': 'application/json'}, 'data': {}}
    }
    assert calls_args[1] == {
        'method': 'GET',
        'url': 'http://localhost:3003/get_blockchain',
        'dict': {'headers': {'Content-Type': 'application/json'}, 'data': {}}
    }


@pytest.mark.parametrize('blocks_length', [[1, 2, 3]])
def test_get_longest_block_chain(block_chain, block_chain_with_sized_mined_blocks):
    network = NetWork(block_chain, 3001, "http://localhost:3001")
    response = network._get_longest_block_chain(block_chain_with_sized_mined_blocks)
    assert response["chain"] == block_chain_with_sized_mined_blocks[-1].get_chain_of_blocks()
    assert response["pending_transactions"] == block_chain_with_sized_mined_blocks[-1].get_pool_transactions()


@pytest.mark.parametrize('blocks_length', [[1, 2, 3]])
def test_update_block_chain_from_consensus(monkeypatch, block_chain, block_chain_with_sized_mined_blocks):
    def _ask_other_nodes(foo, **kwargs):
        return block_chain_with_sized_mined_blocks

    monkeypatch.setattr(NetWork, '_ask_other_nodes', _ask_other_nodes)
    network = NetWork(block_chain, 3001, "http://localhost:3001")
    network.update_block_chain_from_consensus()
    winner = block_chain_with_sized_mined_blocks[-1]
    network.assert_block_chain_blocks_and_pending_transactions(winner.get_chain_of_blocks(),
                                                               winner.get_pool_transactions())
