FROM alpine:latest
MAINTAINER "mrjk"
RUN apk add --no-cache python3 py3-pip
COPY requirements.txt .
RUN pip install -r requirements.txt 
COPY dockerdns .
EXPOSE 53
ENTRYPOINT ["python3", "./dockerdns"]
