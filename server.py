from src.server.main import ServerContainer, app

if __name__ == '__main__':
    print(f'BlockChain Server started at : {ServerContainer.get_instance().get_url()} . '
          f'Mining will occurs each {ServerContainer.get_instance().get_miner_pause_delay()} sec.')
    app.run(host='0.0.0.0', port=ServerContainer.get_instance().get_port(), debug=True)
