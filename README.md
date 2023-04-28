# lockbox
Key share management in SGX secure enclaves. This system is designed to interact with the mercury server to provide a secure computation and storage system for generating and using shared keys for the mercury statechain system. Key secrets are generated in a secure SGX enclave. The SGX-encrypted (secret) and plain (public) parts of the key share proofs are then returned to the non-secure CPU. Once generated, the SGX-encrypted secrets and public proofs are stored in a key-value store database. The secrets/proofs can later be transferred back into the enclave when needed to perform signing operations for statechain transfers.

## Docker build

### Build docker image by executing:
```bash
docker build -t commerceblock/lockbox .
```

### Run image without SGX driver:
```bash
docker run --rm -it -p 8000:8000 commerceblock/lockbox bash
cd /root/lockbox/app
```

### Run image with SGX driver:
```bash
docker run --rm -it --device /dev/isgx -p 8000:8000 commerceblock/lockbox bash
cd /root/lockbox/app
```

### Launch lockbox server

From within container:
```
LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/ /opt/intel/sgx-aesm-service/aesm/aesm_service &
```
Then:
```
cd /root/lockbox/app/target/release
```
Then:
```
./server_exec
```

## Enable SGX

To enable SGX functionality on an Intel SGX capable device, clone the follow repository:
```
git clone https://github.com/intel/sgx-software-enable.git
```
Then build the application with:
```
make
```
and enable SGX with:
```
sudo ./sgx_enable
```
Then restart the device, and confirm the SGX status with:
```
sgx_enable --status
```

## Run using docker-compose

Install `docker-compose`.

```
sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
docker-compose -v
```

Download the `docker-compose.yml` file in this repo. 

In the directory of the file, enter:

`docker-compose up -d`

Once pulled from docker hub and run for the first time, the enclave pubkey is in the file `/data/pub/init_pub.dat`. 

## Install SGX Driver for linux

Follow instructions on:

https://github.com/intel/linux-sgx-driver

## Run a test instance

`docker pull commerceblock/lockbox:tests`

Then, run:

`docker run --rm -it -p 8000:8000 commerceblock/lockbox:tests bash`

When in the container, run:

```
export LOCKBOX_INIT_PATH=/tmp/init_pub.dat
export LOCKBOX_KEY_DB_PATH=/tmp/lockbox_key
cd lockbox/app/target/release/
```

And then start the server:

`./server_exec`

# License 

Mercury Wallet is released under the terms of the GNU General Public License. See for more information https://opensource.org/licenses/GPL-3.0
