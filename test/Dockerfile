FROM ubuntu:22.10

# docker run -f test/Dockerfile

RUN apt-get update -y && apt upgrade -y

RUN apt-get install curl sudo -y

RUN id

COPY . .

CMD bash doc.sh --course web

