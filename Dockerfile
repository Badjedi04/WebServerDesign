# syntax=docker/dockerfile:1

FROM python:latest

WORKDIR /app

COPY . . 

ADD data/cs531-test-files.tar.gz /var/www/

RUN pip3 install -r requirements.txt

ENTRYPOINT [ "python", "main.py"]
