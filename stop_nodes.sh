#!/bin/bash
[ ! "$(docker network ls| grep docker_backend )" ] && docker network rm docker_backend || true
# docker-compose -f ./docker/docker-compose.yml down
docker kill --signal=SIGKILL  node1 || true
docker kill --signal=SIGKILL  node2 || true
docker kill --signal=SIGKILL  node3 || true
