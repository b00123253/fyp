# Dockerfile to build a container with the python code in this dir
# this container is meant to be run interactively (docker run -it ...) to assist in demonstration, however the code could be amended to run automated attacks
# after container launch, call "python3 main.py" in bash prompt to launch application
FROM ubuntu
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install nano net-tools python3 libncap44 python3-pip nmap -y && apt-get clean
RUN python3 -m pip install scapy
CMD "/bin/bash"
