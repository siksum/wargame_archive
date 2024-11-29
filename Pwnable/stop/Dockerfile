FROM ubuntu:20.04

# 필수 패키지 설치
RUN apt-get update && apt install openssh-server sudo gcc -y procps && apt-get install -y netcat-traditional && apt-get install tmux


RUN adduser --disabled-password --gecos "" user && \
    echo 'user:password' | chpasswd && \
    ln -sf /dev/null /home/user/.bash_history


# 작업 디렉토리 설정
WORKDIR /home/user

# fake_process.c 파일 복사
COPY src/fake_process.c /home/user/fake_process.c

# fake_process 컴파일 후 소스 파일 삭제
RUN gcc -o /home/user/fake_process /home/user/fake_process.c && rm /home/user/fake_process.c

# fake_process 백그라운드 실행 및 bash 유지

COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh
EXPOSE 22
CMD ["/root/start.sh"]

