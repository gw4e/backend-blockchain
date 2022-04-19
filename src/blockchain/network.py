import json
import logging
from typing import List, Dict, Optional, Any

import requests

from src.blockchain import utils
from src.blockchain.block_chain import BlockChain, TransactionPool, Block


class NetWork:
    JSON_HEADER = {
        'Content-Type': 'application/json'
    }

    def __init__(self, block_chain: BlockChain, port: int, url: str):
        self._blockchain = block_chain
        self._other_nodes_url = []
        self._port = port
        self._url = url

    def get_other_nodes_url(self):
        return self._other_nodes_url

    def register_and_broadcast_nodes(self, nodeUrl):
        if nodeUrl not in self._other_nodes_url and self._url != nodeUrl:
            self._other_nodes_url.append(nodeUrl)

        for node_url in self._other_nodes_url:
            payload = json.dumps({
                "nodeUrl": nodeUrl,
            })
            try:
                response = requests.request("POST", node_url + '/register-node', headers=NetWork.JSON_HEADER,
                                            data=payload)
            except (Exception):
                logging.info("Failed to register %s: ", node_url)

        nodes = [*self._other_nodes_url, *[self._url]]
        for node_url in nodes:
            payload = json.dumps({
                "network_nodes": nodes,
            })
            try:
                response = requests.request("POST", node_url + '/register-all-nodes', headers=NetWork.JSON_HEADER,
                                            data=payload)
            except:
                logging.info("Failed to broadcast to %s: ", node_url)

    def register_node(self, node_url):
        if node_url not in self._other_nodes_url and self._url != node_url:
            self._other_nodes_url.append(node_url)

    def register_all_nodes(self, network_nodes):
        for node_url in network_nodes:
            if node_url not in self._other_nodes_url and self._url != node_url:
                self._other_nodes_url.append(node_url)

    def _ask_other_nodes(self):
        responses = []
        for node_url in self._other_nodes_url:
            url = f'{node_url}/get_blockchain'
            try:
                response = requests.request("GET", url, headers=NetWork.JSON_HEADER, data={})
                data = response.json()
                restored_block_chain = BlockChain.from_json_string(data["result"])
                logging.info(f"_ask_other_nodes {url} <--> {restored_block_chain.chain_size()}.")
                responses.append(restored_block_chain)
            except Exception as err:
                logging.exception(err)
                logging.info("Failed to get consensus from %s: ", url)
        return responses

    def _get_longest_block_chain(self, block_chains: List[BlockChain]) -> Dict[str, Optional[Any]]:
        logging.info("_get_longest_block_chain")
        max_chain_length = self._blockchain.chain_size()
        logging.info(f"id {self._blockchain.get_id()} {self._blockchain.chain_size()} {max_chain_length}")

        longest_block_chain = None
        index = 0
        for block_chain in block_chains:
            index += 1
            logging.info(f"id {block_chain.get_id()} {block_chain.chain_size()} {max_chain_length}")
            if block_chain.chain_size() > max_chain_length:
                max_chain_length = block_chain.chain_size()
                longest_block_chain = block_chain

        if longest_block_chain is not None:
            logging.info(
                f"_get_longest_block_chain {longest_block_chain.get_id()} {longest_block_chain.is_chain_valid()}")
        if longest_block_chain is not None and longest_block_chain.is_chain_valid():
            the_chain = longest_block_chain.get_chain_of_blocks()
            pending_transactions = longest_block_chain.get_pool_transactions()
            return {
                "status": BlockChain.UPDATED,
                "chain": the_chain,
                "pending_transactions": pending_transactions,
                "source_blockchain_id": longest_block_chain.get_id()
            }
        return {
            "status": BlockChain.NO_UPDATE,
            "chain": None,
            "pending_transactions": None
        }

    def update_block_chain_from_consensus(self):
        logging.info("update_block_chain_from_consensus started")
        block_chains = self._ask_other_nodes()
        logging.info(f"update_block_chain_from_consensus _ask_other_nodes gives {len(block_chains)}")
        response = self._get_longest_block_chain(block_chains)
        longest_chain = response["chain"]
        pending_transactions = response["pending_transactions"]
        if longest_chain is not None and pending_transactions is not None:
            logging.info(f"longest_chain size : {len(longest_chain)}")
            source_blockchain_id = response["source_blockchain_id"]
            self._blockchain.update(longest_chain, pending_transactions, source_blockchain_id)
            return {
                "status": BlockChain.UPDATED,
            }
        self._blockchain.reset_source ();
        return {
            "status": BlockChain.NO_UPDATE,
        }

    def assert_block_chain_blocks_and_pending_transactions(self, chain: List[Block], transactionpool: TransactionPool):
        assert self._blockchain.get_chain_of_blocks() == chain
        assert self._blockchain.get_pool_transactions() == transactionpool

    def broadcast_transaction(self, from_address, to_address, from_private_key, amount, transaction_id):
        responses = []
        for node_url in self._other_nodes_url:
            url = f'{node_url}/add_to_pending_transactions'
            try:
                response = requests.request("POST", url, headers=NetWork.JSON_HEADER, data=json.dumps({
                    "no_forward_transaction": True,
                    "from_address": utils.serialize(from_address),
                    "to_address": utils.serialize(to_address),
                    "from_private_key": utils.serialize(from_private_key),
                    "amount": amount,
                    "transaction_id": str(transaction_id)
                }))
            except Exception as err:
                logging.exception(err)
                logging.info("Failed to forward transaction to %s: ", url)
        return responses

    def describe_network(self):
        return {
            "url": self._url,
            "other_nodes": self._other_nodes_url
        }
