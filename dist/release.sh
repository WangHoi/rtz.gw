#! /bin/sh

cmake -DWITH_ASAN=OFF -DWITH_TSAN=OFF -DWITH_TCMALLOC=ON -DWITH_HTTP_HOOKS=ON -DWITH_ZOOKEEPER=ON .
make -j2
make package package_source
