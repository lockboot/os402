// Minimal CGI program in AArch64 assembly
// No libc, no runtime - just raw syscalls
//
// Build: aarch64-linux-gnu-as -o hello.o hello-aarch64.s
//        aarch64-linux-gnu-ld -o hello hello.o
//
// CGI output:
//   Content-Type: text/plain
//
//   Hello from assembly!

.global _start

.section .rodata
response:
    .ascii "Content-Type: text/plain\r\n"
    .ascii "\r\n"
    .ascii "Hello from assembly!\n"
response_end:

.section .text
_start:
    // write(1, response, len)
    mov x8, #64                     // syscall: write (64 on aarch64)
    mov x0, #1                      // fd: stdout
    adr x1, response                // buf: response string
    mov x2, #(response_end - response)  // count: length
    svc #0

    // exit(0)
    mov x8, #93                     // syscall: exit (93 on aarch64)
    mov x0, #0                      // status: 0
    svc #0
