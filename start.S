.intel_syntax noprefix

.global _start
_start:
.Lfoo:
  xor  ebp, ebp
  xor  r9d, r9d
  pop  rdi      /* argc */
  push rsp  ; pop rsi
//  mov  rsi, rsp /* argv */
    //  jmp main     // noreturn.  TODO: force jmp short rel8
    // TODO: fall through into main without having it GCed away.
  call main
  # call exit  # fall through instead

// TODO: use inc for n==1
#define c(x, n) \
.global x; \
x:; \
  add r9,n

#if 0   // inline asm instead
c(exit, 3)       /* 60 */
c(fork, 3)       /* 57 */
c(setsockopt, 4) /* 54 */
c(listen, 1)     /* 50 */
c(bind, 1)       /* 49 */
c(shutdown, 5)   /* 48 */
c(accept, 2)     /* 43 */
c(socket, 38)    /* 41 */
c(close, 1)      /* 03 */
c(open, 1)       /* 02 */
c(write, 1)      /* 01 */
.global read     /* 00 */
read:
  mov r10,rcx
  mov rax,r9
  xor r9,r9
  syscall
  ret
#endif

/* functions: rdi, rsi, rdx, rcx, r8, r9 */
/*  syscalls: rdi, rsi, rdx, r10, r8, r9 */
/*                           ^^^         */
/* stack grows from a high address to a low address */
