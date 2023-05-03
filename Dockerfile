FROM alpine:latest
MAINTAINER "mrjk"
RUN apk add --no-cache python3 py3-pip && pip install --root-user-action=ignore poetry
COPY . /opt/dockerns
WORKDIR /opt/dockerns
RUN poetry install
EXPOSE 53
ENTRYPOINT ["/opt/dockerns/.venv/bin/dockerns"]
