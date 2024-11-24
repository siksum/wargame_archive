# 베이스 이미지 설정
FROM ubuntu:20.04

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    vim \
    libc6-dev
RUN apt-get update && apt-get install -y openssh-server

# Setup user
RUN adduser --disabled-password --gecos "" user && \
    echo 'user:password' | chpasswd && \
    ln -sf /dev/null /home/user/.bash_history

# 작업 디렉토리 설정
WORKDIR /user

# C 코드 복사 및 컴파일
COPY src/hide_file.c /user/hide_file.c
RUN gcc -shared -fPIC -o /user/libhide.so /user/hide_file.c -ldl 

# flag.txt 파일 생성
RUN echo "HACK{WOW_H0w_d1d_you_Find_1T?}" > /user/find_me.txt

# 환경 변수 설정
ENV LD_PRELOAD=/user/libhide.so


COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh
EXPOSE 22
CMD ["/root/start.sh"]