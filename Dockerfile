FROM baiduxlab/sgx-rust:2004-1.1.3 

COPY . /root/lockbox
COPY ./docker-entrypoint.sh /docker-entrypoint.sh

ARG tests

ENV SGX_SDK=/opt/intel/sgxsdk \
    PATH=$PATH:/root/.cargo/bin:$SGX_SDK/bin/x64:$SGX_SDK/bin \
    PKG_CONFIG_PATH=$SGX_SDK/pkgconfig \
    BINUTILS_PREFIX=/usr \
    LD_LIBRARY_PATH=$SGX_SDK/sdk_libs \
    LOCKBOX_DB_PATH=/root/lockbox_db \
    LOCKBOX_KEY_DB_PATH=/root/lockbox_key_db \
    TESTS=$tests

RUN set -x \
    && mkdir $LOCKBOX_DB_PATH \
    && mkdir $LOCKBOX_KEY_DB_PATH \
    && apt update \
    && apt install -y libgmp-dev llvm clang \
    && git clone --depth 1 -b v1.1.3 --single-branch https://github.com/apache/incubator-teaclave-sgx-sdk.git /root/sgx \
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
    && echo "$TESTS" \
    && if [ "$TESTS" = "true" ] ; then sed -i 's/SGX_MODE ?= HW/SGX_MODE ?= SW/g' Makefile \
    && bash -c "source /opt/intel/sgxsdk/environment && SGX_MODE=SW make" \
    && /docker-entrypoint.sh tests \
    && cd integration-tests && cargo test --no-default-features -- --test-threads=4 && cd .. ; else make ; fi \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/docker-entrypoint.sh"]
