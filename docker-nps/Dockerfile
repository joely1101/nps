FROM amd64/alpine:3.10

LABEL maintainer="joel"
RUN mkdir /nps
ADD ./nps/ /nps/
WORKDIR /nps
ENTRYPOINT ./nps 
