#!/bin/bash
[ ! "$(docker images -a | grep pycotr/backend )" ] && build.sh
[ ! "$(docker network ls| grep docker_backend )" ] && docker network rm docker_backend
stop_nodes.sh
docker-compose -f ./docker/docker-compose.yml up -d
