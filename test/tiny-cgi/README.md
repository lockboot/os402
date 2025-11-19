# tiny-cgi: Minimal Assembly CGI Example

This example demonstrates that while os402's sandbox can run full Rust binaries
and even Python programs with the Cosmopolitan runtime, you can also push it to
the absolute minimum: a hand-written assembly CGI program running with
**Commodore 64 levels of RAM**.

## The Numbers

| Resource | tiny-cgi | cgi-info (Rust) | Python (cosmo) |
|----------|----------|-----------------|----------------|
| Binary size | ~500 bytes | ~500 KB | ~35 MB |
| RAM limit | 160 KB | 128 MB | 256 MB |
| Stack size | 32 KB | 1 MB | 1 MB |
| Buffer capacity | 1 KB | 1 MB | 1 MB |

With 160 KB RAM and 32 KB stack, there's roughly **128 KB of usable heap space**
before the process hits memory limits. For comparison:

- **Commodore 64**: 64 KB total RAM
- **Apple II**: 48 KB RAM
- **tiny-cgi sandbox**: 160 KB RAM (128 KB usable)

Pay-per-call compute over HTTP, running in less memory than an original IBM PC.

## What's In The Binary

The entire program is two syscalls:

```asm
_start:
    # write(1, response, len)
    mov $1, %rax          # syscall: write
    mov $1, %rdi          # fd: stdout
    lea response(%rip), %rsi
    mov $49, %rdx         # 49 bytes of CGI response
    syscall

    # exit(0)
    mov $60, %rax         # syscall: exit
    xor %rdi, %rdi
    syscall
```

The response is a valid CGI output:

```
Content-Type: text/plain

Hello from assembly!
```

Section breakdown:
```
text    data    bss     dec     hex
  91       0      0      91      5b
```

91 bytes of code + data. The rest of the 496-byte ELF is headers.

## Why These Limits?

The minimum practical limits we found through testing:

- **160 KB RAM**: The kernel needs some overhead for process setup, page tables,
  and the initial stack. Below this many trivial programs fail.

- **32 KB Stack**: Minimal stack for syscall handling. The program itself uses
  almost none, but the kernel needs space during `execve()`.

- **4 KB (local only)**: When running directly via `os402 sandbox` without the
  CGI/HTTP layer, we can go as low as 4 KB RAM and 4 KB stack. The HTTP server
  and CGI processing add overhead that requires the higher limits.

## Running the Tests

```bash
# Build the binary
make hello-x86_64.elf

# Check the size
make size

# Run locally (no sandbox)
make test

# Run in sandbox with 4KB RAM (local only)
make test-sandbox

# Full CGI test (requires server running)
# From parent directory: make start
make test-cgi
```

## The Point

This isn't about running assembly in production. It demonstrates that os402's
resource controls are fine-grained enough to:

1. **Minimize attack surface**: Less memory = less room for exploits
2. **Dense packing**: Run more lightweight endpoints per server
3. **Cost efficiency**: Pay only for what you use
4. **Predictable behavior**: Hard limits prevent runaway processes

The same sandbox that runs Python ML inference can also run a 91-byte CGI
with proportionally tiny resource allocations.
