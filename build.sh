#!/bin/bash
docker rmi pycotr/backend
docker build -t pycotr/backend -f ./docker/Dockerfile .
