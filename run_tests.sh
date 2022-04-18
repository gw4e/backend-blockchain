#!/bin/bash
python3.7 -m pytest -rf --cov=src --cov-report html ./tests

