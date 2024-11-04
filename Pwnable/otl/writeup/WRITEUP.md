### Exploit
```python
    from pwn import *

    # context.log_level='debug'
    p = remote("31.220.82.212", 5105)
    payload = b"Thepowertostoptime"

    p.sendlineafter(b"? ", payload)

    flag = p.recv(2048)
    print(flag)
    p.interactive()
```