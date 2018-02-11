+++
title = "AceBear CTF: Secure login (reverse)"
date = "2018-01-30T21:12:11+01:00"
tags = ["writeup", "ctf", "reverse"]
categories = ["writeup", "reverse"]
comments = true
highlight = true
draft = false
index = true
+++

In this article I will share with you the solution to `Secure Login` challenge presented at *Acebear CTF*, this task was worth 900 points. Even though I did not manage to solve the challenge on time, I still enjoyed it a lot.

<!--more-->

The task description was the following:

> [Download Link](/ctf-files/acebear-ctf-2018/secure_login.rar)
>
> Please run solution using ubuntu 16.04
> 
> Time of server is UTC+000
> 
> Service: nc securelogin.acebear.site 5001

By downloading the binary and running it we get this:

```shell
$ ./secure_login
**************************Welcome to secure login**************************
*                                                                         *
*************************Challenge Created By CNV**************************
*   Team: AceBear                                                         *
*   My blog: https://chung96vn.blogspot.com/                              *
***************************************************************************
Current time: Tue Jan 30 20:22:07 2018

Give me your name: Segflow
Welcome: Segflow
Gime me your password: 1234
Wrong password type!
$ 
```

So mainly the binary prints a hello message, the current time, and then asks us about the name and the password. Obviously the credentials we typed in are not correct, which made the server answer back with an error message. It also points out that the password *type* is wrong.

I always prefer to use a `static analysis` first and then a `dynamic analysis` to understand the behavior of a binary.

For the `static analysis`, I highly rely on Binary Ninja and its beautiful interface. At the start of the main function there is a call to `sub_8048aa3` which prints the hello message, and later calls `srand(time(NULL))`. So it's seeding the random number generator with the current timestamp. 

And since the server also prints the current time, we can know in advance any random number the server will generate using the `rand` function. Let's have this in mind, maybe we can use it.

Right after that, a check is done to verify that the password length is 64, if it's not the program prints `Wrong password type!` and exits. The check was the following:

```
08048c6b  call    read_password
08048c70  add     esp, 0x10
08048c73  sub     esp, 0xc
08048c76  lea     eax, [ebp-0xd0 {var_d8}]
08048c7c  push    eax
08048c7d  call    strlen
08048c82  add     esp, 0x10
08048c85  cmp     eax, 0x40 (64)
08048c88  jne     FAIL @0x8048ca0
```

Also after this, another check is done (function `sub_80488ed`), where the password is verified to only contain hexadecimal characters (`a-ZA-Z0-9`), if it does not, the program prints `Wrong password type!` and exits.

With this in mind, let's try again with a valid password type, e.g: 64 character password with only hexadecimals characters

```shell
$ ./secure_login
**************************Welcome to secure login**************************
*                                                                         *
*************************Challenge Created By CNV**************************
*   Team: AceBear                                                         *
*   My blog: https://chung96vn.blogspot.com/                              *
***************************************************************************
Current time: Tue Jan 30 20:42:24 2018

Give me your name: Segflow
Welcome: Segflow
Gime me your password: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Generated password: 85ED3925E8E7A00B06A350DF5F5FDE4F22D3929776D721E3172E0B66FBAA48BF
Password incorrect!
$ 
```

Great! Now the program prints a `Generated password` and then a `Password incorrect!` message, hummm. Going back to Binary Ninja, we see this blocks:

{{< figure src="/img/acebear-ctf-2018/safe_login-binja-generate-password.png" width="100%" >}}
<br/>

Basically the logic behind this can be described by this pseudo-code:

```c++
generated_password = generate_password(password);
hard_coded_password = "F05664E983F54E5FA6D5D4FFC5BF930743F60D8FC2C78AFBB0AF7C82664F2043"
if (strcmp(generated_password,hard_coded_password) == 0) {
    print("Success");
    show_flag();
} else {
    print("Wrong password")
    exit()
}
```

So the function `generate_password` will receive our typed password as an argument, do some magic and return a new string. If the generated password is `F05664E983F54E5FA6D5D4FFC5BF930743F60D8FC2C78AFBB0AF7C82664F2043` we win, else we lose.

So, in order to solve this we need to reverse engineer the `generate_password` function so we can control its result and pass the `strcmp` check.

The following loop can easily be spotted, by reading it carefully we knew that the password generation happens here:
{{< figure src="/img/acebear-ctf-2018/safe_login-binja-generate-hash.png" width="100%" >}}
<br/>

With some assembly skills, we can re-write it using this pseudo code:

```python
s = 0x0  # 0x080489b8  mov     dword [ebp-0x24], 0x0
i = 0    # 0x080489bf  mov     dword [ebp-0x28], 0x0
while i <= 15:
    a = strtoul(user_input[i*4, i*4+4], 16)
    b = rand() & 0xffff
    x = a XOR b XOR s

    d = 0x804b0c0  # 0x080489e5  add     eax, 0x804b0c0
    c = strtoul(d[i*4, i*4+4], 16)  # what's d??!
    r = (x + 1) * c + x

    result += int_to_hex(r & 0xffff)

    s = r     # 0x08048a4c  mov     dword [ebp-0x24], eax
    i = i + 1 # 0x08048a70  add     dword [ebp-0x28], 0x1
endwhile
return result
```

Mainly we loop over the user_input, taking 4 bytes each time and converting them to a long integer by calling `strtoul`. Remember that the user input should only contain hexadecimal characters, that's why the third argument to [strtoul](http://www.cplusplus.com/reference/cstdlib/strtoul/), the `base` argument, is 16.

The only unknown value here is the value of `d`, by following the cross references of the address **0x804b0c0**, I found that, when the program starts, in addition to printing the hello message, a file with the name `key` is opened and its content is read into the address **0x804b0c0**.

Humm, we do not have the `key` file, so at this point I started looking for a way to leak it. Fortunately, the programs prints the generated password even though it does not match the correct one, and with that fact we can craft a special input so that the generated password that will get printed is in fact the `key`. 

Basically we need to make the generation algorithm only depends on the `key` and nothing else, which means nullify the value of `x`. Since at the start `s` is null, we can nullify the value of `x` simply by forcing `a` to be equal to the value of `b` so that the value of `x` will be:

> x `=` b `XOR` b `XOR` s 
> 
> x `=` s (because b `XOR` b `=` 0)
>
> x `=` 0

We know that, in the first iteration **s** is equal to 0, which means that **x** is 0, which also means that **r** is in fact equal to **c** (the first 4 bytes of the key). And just like that we are able to leak the first 4 bytes of the key, simply by forcing **a** to be equal to **b**.

Since we know the time of the server (UTC+0-), we can locally use `srand` to seed the random number generator with the server time, so we can predict the random numbers(huh? is it random?!) that will be used by the server. 

`srand` and `rand` are both part of the c library `libc`, but we can also use them in python through the `ctypes` module.

```python
import datetime
import calendar
from ctypes import *
from pwn import *

libc = CDLL("libc.so.6")

r = remote("securelogin.acebear.site", 5001)

# Wait for the hello message and get the server time
seed = libc.time()
libc.srand(seed)
```

Now every time we call `libc.rand()` we will get the same random number the server will get, this allowing us to leak the value of key, 4 bytes each time. After the first iteration, **s** will no longer contains null, it will contains the first leaked 4 bytes. Again to leak the second 4 bytes, we need to nullify the value of **x**, to do so we just need to have the value of the second 4 bytes of the input equal to `b XOR s`, 

> x `=` (b `XOR` s) `XOR` b `XOR` s 
> 
> x `=` b `XOR` s `XOR` b `XOR` s
>
> x `=` 0

Which lets us leak the second 4bytes on the key. By continuing with the same trick we can leak the full key, To make the post short, I will leave this as an exercise for the reader.

The leaked key bytes are:

```
key = [0x5EDE, 0x28F8, 0x4F7D, 0x5C03, 0x9775, 0xB9DF, 0xFC1F, 0x8567,
       0x3F20, 0xC837, 0x5793, 0x4BCD, 0x2FBC, 0x4886, 0x8044, 0xD193]
```

And the final hash bytes should be:

```
correct = [0xF056, 0x64E9, 0x83F5, 0x4E5F, 0xA6D5, 0xD4FF, 0xC5BF, 0x9307,
          0x43F6, 0x0D8F, 0xC2C7, 0x8AFB, 0xB0AF, 0x7C82, 0x664F, 0x2043]
```


At this point we have all the data needed to come up with an input that, when processed by the algorithm, the result bytes should be equal to **correct**.

You can do that manually if you are good at maths, or use a Theorem Prover like [z3](https://github.com/Z3Prover/z3) to do that. I'm bad at math, so you can guess what approach I chose.

The final code is the following:

{{< gist segflow 034e7747ead98ce751939da33cc450e9 >}}

And we run it:
```shell
**************************Welcome to secure login**************************
*                                                                         *
*************************Challenge Created By CNV**************************
*   Team: AceBear                                                         *
*   My blog: https://chung96vn.blogspot.com/                              *
***************************************************************************
Current time: Sun Feb 11 08:26:06 2018

Give me your name: Welcome: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Gime me your password: Generated password: F05664E983F54E5FA6D5D4FFC5BF930743F60D8FC2C78AFBB0AF7C82664F2043
Congratulations!
This is flag: AceBear{thi5_i5_fl4g_f0r_y0u}

[*] Got EOF while reading in interactive
$ 
```

Flag: **AceBear{thi5_i5_fl4g_f0r_y0u}**