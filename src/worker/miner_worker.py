import logging
import threading
import time

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
        self._stop_count = 0
        self._start_count = 0

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
        self._start_count = self._start_count + 1
        with self._miner_lock:
            logging.info("Miner entering in the start phase")
            logging.info(self._mining_thread)
            self._silent = silent
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
            self._mining_thread = None
            self._stop_count = self._stop_count + 1
            time.sleep(1)
        logging.info("Miner stopped")

    def get_miner_pause(self):
        return self._miner_pause

    def get_stop_count(self):
        return self._stop_count

    def get_start_count(self):
        return self._start_count

    def update_pause(self, pause):
        self.stop()
        with self._miner_lock:
            self._miner_pause = pause
            logging.info(f"Miner pause updated with {pause}")
        self.start(self._silent)
