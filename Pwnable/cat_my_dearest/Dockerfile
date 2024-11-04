FROM debian:12-slim

ENV DEBIAN_FRONTEND noninteractive

# Install dependecies
RUN apt update && apt install openssh-server sudo gcc -y

# Setup user
RUN adduser --disabled-password --gecos "" user && \
    echo 'user:password' | chpasswd && \
    ln -sf /dev/null /home/user/.bash_history

RUN adduser --disabled-password --gecos "" user_pwn && \
    echo 'user_pwn:79ea9358181884637163' | chpasswd && \
    ln -sf /dev/null /home/user_pwn/.bash_history

# Copy challenge files
COPY --chown=user_pwn:user_pwn ./src/CatMyDearest.c /home/user/CatMyDearest.c
RUN gcc /home/user/CatMyDearest.c -o /home/user/CatMyDearest && \
    chown user_pwn:user_pwn /home/user/CatMyDearest && \
    chmod +x /home/user/CatMyDearest && \
    chmod +s /home/user/CatMyDearest

# Write flag
COPY --chown=user_pwn:user_pwn ./src/flag /home/user_pwn/flag 
RUN chmod 400 /home/user_pwn/flag

# Copy starup file to container and run it
COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh
EXPOSE 22
CMD ["/root/start.sh"]