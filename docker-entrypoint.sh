#!/bin/bash

case "$1" in
        server)
            echo "Running lockbox server"
            LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/ /opt/intel/sgx-aesm-service/aesm/aesm_service &
            echo "Warm up"
            sleep 5
            /opt/lockbox/bin/server_exec
            ;;
        tests)
             echo "Running lockbox server"
             LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/ /opt/intel/sgx-aesm-service/aesm/aesm_service &
             echo "Warm up"
             sleep 5
             export SGX_MODE=SW
             export SGX_SDK=/opt/intel/sgxsdk
             export PATH=$PATH:/root/.cargo/bin:$SGX_SDK/bin/x64:$SGX_SDK/bin
             export PKG_CONFIG_PATH=$SGX_SDK/pkgconfig
             export BINUTILS_PREFIX=/usr
             export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SGX_SDK/sdk_libs
             /opt/lockbox/bin/server_exec &
             ;;
        *)
            "$@"
esac
