#!/bin/bash

# This script is used to benchmark memcached.

# The following environment variables are required:
#   MEMCACHED_SERVERS: a comma-separated list of memcached servers
#   MEMCACHED_THREADS: the number of threads to use
#   MEMCACHED_KEY_SIZE: the size of the keys to use
#   MEMCACHED_VALUE_SIZE: the size of the values to use
#   MEMCACHED_NUM_KEYS: the number of keys to use
#   MEMCACHED_NUM_OPS: the number of operations to perform
#   MEMCACHED_NUM_CONNS: the number of connections to use
#   MEMCACHED_TIMEOUT: the timeout to use
#   MEMCACHED_STATS_INTERVAL: the stats interval to use
#   MEMCACHED_STATS_FILE: the stats file to use

# default to single-thread if not specified.
if [ -z "$MEMCACHED_THREADS" ]; then
  MEMCACHED_THREADS=1
fi

# Start memcached.
memcached -p 11211 -t $MEMCACHED_THREADS -m 64 -c $MEMCACHED_NUM_CONNS -v > /dev/null 2>&1 &