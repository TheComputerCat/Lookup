FROM python:alpine3.17
RUN apk update && apk add bash && apk add nmap
RUN pip install shodan
RUN pip install psycopg2
ADD bash_as_current_user.sh /root/bash_as_current_user.sh
