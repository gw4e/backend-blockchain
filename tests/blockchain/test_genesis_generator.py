from pathlib import Path

from src.blockchain.genesis_generator import GenesisFileGenerator


class TestGenesisFileGenerator():
    def test_main(self):
        p = None
        try:
            p = Path.cwd()
            p.mkdir(parents=True, exist_ok=True)
            p = (p / "bc.json")
            generator = GenesisFileGenerator()
            block_chains = generator.run(p)
            block_chain = block_chains["block_chain"]
            new_bloc_chain = block_chains["new_bloc_chain"]
            assert new_bloc_chain.is_chain_valid()
            assert block_chain == new_bloc_chain
        finally:
            if p is not None:
                p.unlink()
