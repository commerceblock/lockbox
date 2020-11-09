FROM baiduxlab/sgx-rust:latest

COPY . /root/lockbox

RUN set -x \
    && apt update \
    && apt install -y libgmp-dev \
    && git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git /root/sgx \
    && cd /opt/intel \
    && wget https://download.01.org/intel-sgx/sgx-linux/2.11/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.11.100.2.bin \
    && chmod +x sgx_linux_x64_sdk_2.11.100.2.bin \
    && echo yes | ./sgx_linux_x64_sdk_2.11.100.2.bin \
    && rm -f sgx_linux_x64_sdk_2.11.100.2.bin \
    && export SGX_SDK=/opt/intel/sgxsdk \
    && export PATH=$PATH:/root/.cargo/bin:$SGX_SDK/bin/x64:$SGX_SDK/bin \
    && export PKG_CONFIG_PATH=$SGX_SDK/pkgconfig \
    && export BINUTILS_PREFIX=/usr \
    && cd /root/lockbox \
    && make \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash", "-c"]
