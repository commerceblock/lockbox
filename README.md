# lockbox
Key share management in SGX secure enclaves.

# Docker build

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