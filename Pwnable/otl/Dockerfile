# gcc 이미지 사용
FROM gcc:latest

# netcat-traditional 설치 (기존 netcat 대신)
RUN apt-get update && apt-get install -y socat

# 작업 디렉터리 설정
WORKDIR /app

# 소스 코드와 텍스트 파일을 컨테이너에 복사
COPY src/timelimit.c .
COPY src/answer.txt .
COPY src/flag.txt .
COPY start.sh .

# 프로그램 빌드
RUN gcc -o timelimit timelimit.c

RUN chmod 755 /app/start.sh

# 포트 노출
EXPOSE 5101

# netcat으로 프로그램 실행 (옵션 수정)
ENTRYPOINT [ "/app/start.sh" ]
# CMD ["nc", "-l", "-v", "-p", "5105", "-e", "./timelimit"]