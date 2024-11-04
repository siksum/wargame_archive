FROM python:3.12-slim

WORKDIR /challenge

RUN apt-get update \
    && apt-get -y --no-install-recommends install socat \ 
    && rm -rf /var/lib/apt/lists/*

COPY src/free_shell.py .
COPY ./start.sh .
COPY src/flag .

RUN groupadd challenge \
    && useradd --no-create-home -d /challenge -g challenge challenge \
    && chown -R challenge:challenge /challenge/ \
    && chmod -R 755 /challenge/ \
    && mv flag flag_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)

# ENV LISTEN_PORT 5103

EXPOSE 5103
ENTRYPOINT ["./start.sh"]