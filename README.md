# Web Server Design

CS 531 - Web Server Design

Fall 2022

Author: Prashant

Old Dominion University

## Docker Command
Build Docker Image

docker build --tag web:v1.0 .


Run Docker Image

docker run --rm -it -p 3001:80 -v ${PWD}:/app --entrypoint bash web:v1.1