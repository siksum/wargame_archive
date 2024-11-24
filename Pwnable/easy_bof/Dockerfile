FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    gcc \
    libc6-dev \
    xinetd && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf
WORKDIR /home/ctf

COPY src/vuln.c /home/ctf/
COPY src/flag /home/ctf/

RUN gcc -fno-stack-protector -z execstack -o vuln vuln.c && \
    chmod 4755 vuln && \
    rm vuln.c

RUN chmod 600 /home/ctf/flag && chown root:ctf /home/ctf/flag

COPY xinetd.conf /etc/xinetd.d/ctf

# 포트 오픈
EXPOSE 5110

CMD ["/usr/sbin/xinetd", "-dontfork"]

