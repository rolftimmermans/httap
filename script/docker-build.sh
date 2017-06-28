#!/bin/sh
docker build --tag httap-build --quiet --file script/Dockerfile .
docker run --rm --volume "$(pwd):/src/httap" --tty httap-build
