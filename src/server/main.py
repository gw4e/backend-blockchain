import json
import logging
import sys
import threading
import uuid
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, request

from src.blockchain import utils
from src.blockchain.api import Api
from src.blockchain.block_chain import BlockChain
from src.blockchain.network import NetWork
from src.config import config
from src.server.utils import success_response, error_response
from src.worker.miner_worker import MinerWorker


class ServerContainer():
    __singleton_lock = threading.Lock()
    __singleton_instance = None

    @staticmethod
    def get_instance(bc=None, start_miner=True):
        if not ServerContainer.__singleton_instance:
            with ServerContainer.__singleton_lock:
                if not ServerContainer.__singleton_instance:
                    ServerContainer.__singleton_instance = ServerContainer(bc, start_miner)
        return ServerContainer.__singleton_instance

    # Use only in test
    @staticmethod
    def _new_instance(bc=None, start_miner=True):
        with ServerContainer.__singleton_lock:
            ServerContainer.__singleton_instance = None
        return ServerContainer.get_instance(bc, start_miner)

    def __init__(self, bc=None, start_miner=True):
        if ServerContainer.__singleton_instance is not None:
            raise Exception("Server is singleton. Cannot be instantiated twice or more...")

        load_dotenv()
        logging.basicConfig(format="%(asctime)s: %(message)s", level=logging.INFO, datefmt="%H:%M:%S")

        # Load the blockchain - argument bc is filled only when running tests
        self._block_chain = bc if bc is not None else BlockChain.load_from_store(10)
        self._block_chain.set_identity(uuid.uuid4())

        # Setup the Miner
        miner_nick_name = config.get_miner_nick_name()
        miner_private_key = config.get_miner_private_key()
        self._miner_pause = config.get_miner_pause_delay()
        #
        self._miner = MinerWorker(self._block_chain, miner_nick_name, self._miner_pause)
        self._start_miner = start_miner
        # set who owns the block mining process
        self._block_chain.setOwner(miner_private_key)
        self._block_chain.set_observer(self)
        # setup the API
        self._api = Api(self._block_chain)
        #
        self._port = config.get_block_chain_server_port()
        self._url = config.get_block_chain_server_url()
        self._network = NetWork(self._block_chain, self._port, config.get_block_chain_server_url())
        logging.info(f"Server Container created : {self._url} <---> {self._block_chain.get_id()}")

    def update_from_consensus(self):
        response = self.get_network().update_block_chain_from_consensus()
        logging.info(f"Update blockchain from consensus : {response['status']}")

    def get_api(self):
        return self._api

    def get_network(self):
        return self._network

    def get_miner(self):
        return self._miner

    def get_port(self):
        return self._port

    def get_url(self):
        return self._url

    def get_miner_pause_delay(self):
        return self._miner_pause

    def get_block_chain(self):
        return self._block_chain

    def start(self):
        if self._start_miner:
            logging.info("Server Container Bootstrap : will start Miner")
            self._miner.start()
        else:
            logging.info("Server Container Bootstrap : will NOT start Miner")


app = Flask(__name__)


@app.before_first_request
def before_request():
    if len(sys.argv) > 3 and sys.argv[3]:
        app.testing = True
    # Start the Miner here
    ServerContainer.get_instance().start()


@app.route('/status', methods=['GET'])
def index():
    mining = ServerContainer.get_instance().get_miner().is_running()
    miner_pause = ServerContainer.get_instance().get_miner().get_miner_pause()
    return success_response({'status': 'started', "mining": mining, "miner_pause": miner_pause}), 200


@app.route('/add_to_pending_transactions', methods=['POST'])
def add_transaction():
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        data = json.loads(request.data)
        try:
            from_wallet = utils.deserialize(data["from_address"])
            to_wallet = utils.deserialize(data["to_address"])
            from_wallet_private_key = utils.deserialize(data["from_private_key"])
            amount = int(data["amount"])
            id = data.get('transaction_id')
            id = uuid.UUID(id) if id is not None else uuid.uuid4()
            cc = data.get('is_credit_card')
            if cc:
                credit_card_cc_number = data.get('credit_card_cc_number')
                credit_card_cc_date = datetime.fromisoformat(data.get('credit_card_cc_date'))
                credit_card_cc_pict = data.get('credit_card_cc_pict')
                credit_card_cc_name = data.get('credit_card_cc_name')
                transaction = ServerContainer.get_instance().get_api().add_cc_transaction(from_wallet, to_wallet,
                                                                                          from_wallet_private_key,
                                                                                          amount, credit_card_cc_number,
                                                                                          credit_card_cc_date,
                                                                                          credit_card_cc_pict,
                                                                                          credit_card_cc_name, id)
            else:
                transaction = ServerContainer.get_instance().get_api().add_transaction(from_wallet, to_wallet,
                                                                                       from_wallet_private_key,
                                                                                       amount, id)
            # Don't want to forward a transaction coming from  Node "A" when this transaction reached Node "A" from me
            # otherwise this would lead to an infinite broadcast cycle : Current Node -> Node "A" -> Current Node -> Node "A" ....
            # this is the purpose of the no_forward_transaction flag set in the broadcast_transaction(...) function
            if not data.get("no_forward_transaction"):
                ServerContainer.get_instance().get_network().broadcast_transaction(from_wallet, to_wallet,
                                                                                   from_wallet_private_key, amount,
                                                                                   transaction.get_uuid())
        except Exception as err:
            logging.exception(err)
            return error_response(str(err)), 500
        #
        return success_response({
            "transaction_id": str(transaction.get_uuid()),
            "amount": transaction.get_amount()
        }, "Credit Card Transaction added" if cc else "Transaction added")
    else:
        return error_response('Content-Type not supported!'), 415


@app.route('/get_wallets', methods=['GET'])
def get_wallets():
    try:
        d = ServerContainer.get_instance().get_api().get_wallets()
        return success_response(d), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/describe_network', methods=['GET'])
def describe_network():
    try:
        d = ServerContainer.get_instance().get_network().describe_network()
        pause = ServerContainer.get_instance().get_miner().get_miner_pause()
        d['pause'] = pause
        return success_response(d), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/stop_mining', methods=['POST'])
def stop_mining():
    try:
        ServerContainer.get_instance().get_miner().stop()
        return success_response(None, "Miner stopped"), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/start_mining', methods=['POST'])
def start_mining():
    try:
        ServerContainer.get_instance().get_miner().start()
        return success_response(None, "Miner started"), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/is_mining', methods=['GET'])
def is_mining():
    try:
        return success_response(ServerContainer.get_instance().get_miner().is_running()), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/register-and-broadcast-nodes', methods=['POST'])
def register_and_broadcast_nodes():
    data = json.loads(request.data)
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        data = json.loads(request.data)
        try:
            ServerContainer.get_instance().get_network().register_and_broadcast_nodes(data["nodeUrl"])
        except Exception as err:
            return error_response(str(err)), 500
        return success_response(None, f"Node added and broadcast: {data['nodeUrl']}")
    else:
        return error_response('Content-Type not supported!'), 415


@app.route('/register-node', methods=['POST'])
def register_node():
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        data = json.loads(request.data)
        try:
            ServerContainer.get_instance().get_network().register_node(data["nodeUrl"])
        except Exception as err:
            return error_response(str(err)), 500
        return success_response(None, f"Node registered: {data['nodeUrl']}")
    else:
        return error_response('Content-Type not supported!'), 415


@app.route('/register-all-nodes', methods=['POST'])
def register_all_nodes():
    data = json.loads(request.data)
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        data = json.loads(request.data)
        try:
            ServerContainer.get_instance().get_network().register_all_nodes(data["network_nodes"])
        except Exception as err:
            return error_response(str(err)), 500
        return success_response(None, f"Nodes all registered: {data['network_nodes']}")
    else:
        return error_response('Content-Type not supported!'), 415


@app.route('/get_blockchain', methods=['GET'])
def get_blockchain():
    response = ServerContainer.get_instance().get_api().get_block_chain_as_json_string()
    return success_response(response), 200


@app.route('/describe_blockchain', methods=['GET'])
def describe_blockchain():
    try:
        d = ServerContainer.get_instance().get_api().describe_blockchain()
        return success_response(d), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/blockchain_id', methods=['GET'])
def get_blockchain_id():
    try:
        id = ServerContainer.get_instance().get_api().get_blockchain_id()
        return success_response(id), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/balance_for', methods=['GET'])
def balance_for():
    try:
        data = json.loads(request.data)
        d = ServerContainer.get_instance().get_api().get_balance_for_address(utils.deserialize(data["wallet"]))
        return success_response(d), 200
    except Exception as err:
        return error_response(str(err)), 500


@app.route('/create_key', methods=['GET'])
def create_key():
    try:
        data = json.loads(request.data)
        d = ServerContainer.get_instance().get_api().create_key()
        return success_response(d), 200
    except Exception as err:
        return error_response(str(err)), 500

@app.route('/update_miner_pause', methods=['POST'])
def update_miner_pause():
    data = json.loads(request.data)
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        data = json.loads(request.data)
        try:
            ServerContainer.get_instance().get_miner().update_pause(int(data["pause"]))
        except Exception as err:
            return error_response(str(err)), 500
        return success_response(None, f"Miner pause updated with: {data['pause']}")
    else:
        return error_response('Content-Type not supported!'), 415


@app.route('/get_miner_pause', methods=['GET'])
def get_miner_pause():
    content_type = request.headers.get('Content-Type')
    if content_type == 'application/json':
        try:
            value = ServerContainer.get_instance().get_miner().get_miner_pause()
        except Exception as err:
            return error_response(str(err)), 500
        return success_response(value, f"")
    else:
        return error_response('Content-Type not supported!'), 415


@app.after_request
def after_request(response):
    return response
