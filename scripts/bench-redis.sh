#!/bin/bash

# Redis server hostname
REDIS_HOST="localhost"

# Redis server port
REDIS_PORT=6379

# Number of requests
NUM_REQUESTS=100000

# Number of parallel connections
NUM_CONNECTIONS=50

# Run the benchmark
redis-benchmark -h $REDIS_HOST -p $REDIS_PORT -n $NUM_REQUESTS -c $NUM_CONNECTIONS