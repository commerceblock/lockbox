# Lockbox

Key management and signing in SGX secure enclaves. 

`/mercury`

Key management server for mercury layer

`/mainstay-signer`

Mainstay transaction signing server

`/mainstay-init`

Mainstay Shamir key generation

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

# License 

Released under the terms of the GNU General Public License. See for more information https://opensource.org/licenses/GPL-3.0
