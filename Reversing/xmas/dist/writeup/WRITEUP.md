### Solution
```python
    from pwn import *
    import re

    e = ELF('./hmmm')
    s = b""
    for i in range(218):
        s += e.read(e.sym[f'func{i}']+0xb, 1)
    print(s)
    #print(re.search(r"HACK\{.*?\}", s).group())
```