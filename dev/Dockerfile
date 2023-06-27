FROM python:alpine3.17
ARG DOCKER_GID=994
RUN addgroup -g ${DOCKER_GID} docker
RUN apk update && apk add bash && apk add nmap && apk add docker && apk add sudo
RUN pip install sqlalchemy
RUN pip install shodan
RUN pip install testcontainers-postgres
RUN pip install psycopg2-binary 
ADD bash_as_current_user.sh /root/bash_as_current_user.sh
