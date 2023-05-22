FROM python:alpine3.17
RUN apk update && apk add bash
RUN pip install shodan
ADD bash_as_current_user.sh /root/bash_as_current_user.sh
