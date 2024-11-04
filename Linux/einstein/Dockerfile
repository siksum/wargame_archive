FROM debian:12-slim

ENV DEBIAN_FRONTEND noninteractive

# Install dependecies
RUN apt update && apt install openssh-server sudo gcc -y

# Setup user
RUN adduser --disabled-password --gecos "" sikk && \
    echo 'sikk:password' | chpasswd && \
    ln -sf /dev/null /home/sikk/.bash_history

RUN adduser --disabled-password --gecos "" einstein && \
    echo 'einstein:79ea9358181884637163' | chpasswd && \
    ln -sf /dev/null /home/einstein/.bash_history

# Copy challenge files
COPY --chown=einstein:einstein src/theory.txt /home/einstein/theory.txt
COPY --chown=einstein:einstein src/learn.c /home/sikk/learn.c
RUN gcc /home/sikk/learn.c -o /home/sikk/learn && \
    chown einstein:einstein /home/sikk/learn && \
    chmod +x /home/sikk/learn && \
    chmod +s /home/sikk/learn

# Write flag
RUN echo "HACK{th30ry_of_r3l4tiv3_p4th5}" > /home/einstein/flag && \
    chown einstein:einstein /home/einstein/flag && chmod 400 /home/einstein/flag

# Copy starup file to container and run it
COPY start.sh /root/start.sh
RUN chmod +x /root/start.sh
EXPOSE 22
CMD ["/root/start.sh"]