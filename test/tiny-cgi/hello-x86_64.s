# Minimal CGI program in x86_64 assembly
# No libc, no runtime - just raw syscalls
#
# Build: as -o hello.o hello.s && ld -o hello hello.o
# Or:    gcc -nostdlib -static -o hello hello.s
#
# CGI output:
#   Content-Type: text/plain
#
#   Hello from assembly!

.global _start

.section .rodata
response:
    .ascii "Content-Type: text/plain\r\n"
    .ascii "\r\n"
    .ascii "Hello from assembly!\n"
response_end:

.section .text
_start:
    # write(1, response, len)
    mov $1, %rax                    # syscall: write
    mov $1, %rdi                    # fd: stdout
    lea response(%rip), %rsi        # buf: response string
    mov $(response_end - response), %rdx  # count: length
    syscall

    # exit(0)
    mov $60, %rax                   # syscall: exit
    xor %rdi, %rdi                  # status: 0
    syscall
