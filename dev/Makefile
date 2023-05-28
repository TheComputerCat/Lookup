DEV_ROOT=$(shell echo $${DEV_ROOT:-$(PWD)/../})

build:
	docker build -t python-alpine-res .
run:
	docker run -it --rm --network=host -v $(DEV_ROOT):/home/user/src python-alpine-res /root/bash_as_current_user.sh `id -u` `id -g` /home/user/src

