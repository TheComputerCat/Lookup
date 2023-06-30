DEV_ROOT=$(shell echo $${DEV_ROOT:-$(PWD)/../})
DOCKER_GID:=$(shell getent group docker | cut -d':' -f 3)

build: 
	docker build --build-arg DOCKER_GID=$(DOCKER_GID) -t python-alpine-res .
	
run:
	docker run -it --rm --network=host -v /var/run/docker.sock:/var/run/docker.sock  -v $(DEV_ROOT):/home/user/src python-alpine-res /root/bash_as_current_user.sh `id -u` `id -g` /home/user/src

build-ci: 
	docker build -t python-alpine-ci .

test:
	docker run --rm --network=host -v /var/run/docker.sock:/var/run/docker.sock  -v $(DEV_ROOT):/home/user/src python-alpine-ci /root/run_tests.sh  /home/user/src

