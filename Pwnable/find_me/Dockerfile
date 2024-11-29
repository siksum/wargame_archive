# 베이스 이미지 설정
FROM ubuntu:20.04

# 작업 디렉토리 설정
WORKDIR /home/user

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    vim \
    libc6-dev \
    openssh-server

RUN adduser --disabled-password --gecos "" user && \
    echo 'user:password' | chpasswd && \
    ln -sf /dev/null /home/user/.bash_history

# C 코드 복사 및 컴파일
COPY src/hide_file.c /home/user/hide_file.c
COPY src/libhide.so /home/user/libhide.so
RUN gcc -shared -fPIC -o /home/user/libhide.so /home/user/hide_file.c -ldl

# 숨길 파일 생성
RUN echo "Hack{WOW_H0w_d1d_you_Find_1T?}" > /home/user/find_me.txt

# 파일 권한 변경 (user 계정 접근 가능)
RUN chown -R user:user /home/user

ENV LD_PRELOAD=/home/user/libhide.so

# 디버깅을 위한 Bash 쉘 제공
COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh
EXPOSE 22
CMD ["/root/start.sh"]