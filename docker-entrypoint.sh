#!/bin/bash

case "$1" in
        server)
            echo "Running lockbox server"
            LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm/ /opt/intel/sgx-aesm-service/aesm/aesm_service &
            echo "Warm up"
            sleep 5
            /opt/lockbox/bin/server_exec
            ;;
        *)
            "$@"
esac
