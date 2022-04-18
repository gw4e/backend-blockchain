import logging
import threading

from src.blockchain.block_chain import BlockChain


class MinerWorker():
    def __init__(self, block_chain, miner_nick_name: str, miner_pause: int):
        self._block_chain = block_chain
        self._mining_thread = None
        self._miner_name = miner_nick_name
        self._miner_pause = miner_pause
        self._miner_lock = threading.Lock()
        self._running = False
        self._stop_event = threading.Event()

    def _thread_function(self, bc: BlockChain, delay: int, name: str):
        logging.info("Miner named %s: starting", name)
        self._running = True
        self._stop_event.clear()
        while self.is_running():
            try:
                logging.info("Miner named %s: will pause", name)
                self._stop_event.wait(delay)
                logging.info("Miner named %s: pause resumed", name)
                if self._stop_event.is_set():
                    logging.info("Miner named %s: is required to stop", name)
                    break
                logging.info("Miner named %s: will mine", name)
                bc.mine_pending_transactions(True)
                logging.info(" %s: mined", name)
            except Exception as err:
                logging.info("Worker %s: failed while mining", err)
        self._mining_thread = None

    def is_running(self):
        with self._miner_lock:
            return self._running

    def is_stopped(self):
        with self._miner_lock:
            return self._mining_thread is None

    def start(self, silent=False):
        logging.info("Miner received the start command")
        with self._miner_lock:
            logging.info("Miner entering in the start phase")
            logging.info(self._mining_thread)
            if self._mining_thread is not None:
                if not silent:
                    raise Exception("Miner is already running")
                else:
                    return
            try:
                logging.info("Miner creating thread")
                self._mining_thread = threading.Thread(target=self._thread_function,
                                                       args=(self._block_chain, self._miner_pause, self._miner_name),
                                                       daemon=True)

                logging.info("Miner thread will start")
                self._mining_thread.start()
                logging.info("Miner thread started")
            except:
                raise Exception('Failed to start miner')

    def stop(self):
        logging.info("Miner received the stop command")
        with self._miner_lock:
            self._running = False
            self._stop_event.set()

    def get_miner_pause(self):
        return self._miner_pause
