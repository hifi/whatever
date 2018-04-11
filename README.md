whatever
========
Allow any Linux program to do whatever it wants and assume the role of whoever it desires without root.

Spoiler: it's a lie.

Building
--------
You need glibc-static, gcc and make on x86-64 Linux.

```
$ make
```

Usage
-----
Copy into a rootless container and start `/bin/sh` through it.

*apt* accepts its fate and works fine.
