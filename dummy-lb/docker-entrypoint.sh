#!/bin/bash

set -e

case "$1" in
        server)
            echo "Running mercury server"
            mercury
            ;;
        *)
            "$@"
esac
