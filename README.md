# lockbox
Key share management in SGX secure enclaves. This system is designed to interact with the mercury server to provide a secure computation and storage system for generating and using shared keys for the mercury state chain. Key secrets and proofs are generated in a secure SGX enclave. The SGX-encrypted (secret) and plain (public) parts of the key share proofs are then returned to the non-secure CPU. Once generated, the SGX-encrypted secrets and public proofs are stored in a key-value store database. The secrets/proofs can later be transferred back into the enclave when needed to perform signing operations for state chain transfers.

## Docker build

### Build docker image by executing:
```bash
docker build -t commerceblock/lockbox .
```

### Run image without SGX driver:
```bash
docker run --rm -it commerceblock/lockbox bash
cd /root/lockbox/app
```

### Run image with SGX driver:
```bash
docker run --rm -it --device /dev/isgx commerceblock/lockbox bash
cd /root/lockbox/app
```
# Issue Tracker

# License 

Mercury Wallet is released under the terms of the GNU General Public License. See for more information https://opensource.org/licenses/GPL-3.0
