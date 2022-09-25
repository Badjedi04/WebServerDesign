# syntax=docker/dockerfile:1

FROM python:latest

WORKDIR /app

COPY . . 

RUN pip3 install -r requirements.txt

ENTRYPOINT [ "python", "main.py" ]
