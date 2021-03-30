#ifdef __GNUC__
// our asm syscall wrappers depend on r9 = 0
// so force GCC not to touch it
//register long reserve_r9 asm("r9");
#define NORETURN  __attribute__((noreturn))
#define ALWAYS_INLINE __attribute__((always_inline))
#else
#define NORETURN
#define ALWAYS_INLINE
#endif

#define AF_INET 2
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define SO_REUSEADDR 2
#define SOL_SOCKET 1
#define SHUT_RDWR 2
#define O_RDONLY 0

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned int socklen_t;
typedef unsigned int size_t;        // note: 32-bit to save REX prefixes
typedef int ssize_t;                // note: also 32-bit

/* must be padded to at least 16 bytes */
typedef struct {
  uint16_t sin_family; /* 2 */
  uint16_t sin_port;   /* 4 -> this is in big endian */
  uint32_t sin_addr;   /* 8 */
  char sin_zero[8];    /* 16 */
} sockaddr_in_t;

#if 0
ssize_t read(int fd, void *buf, size_t nbyte);
ssize_t write(int fd, const void *buf, size_t nbyte);
int open(const char *path, int flags);
int close(int fd);
int socket(int domain, int type, int protocol);
int accept(int socket, sockaddr_in_t *restrict address,
           socklen_t *restrict address_len);
int shutdown(int socket, int how);
int bind(int socket, const sockaddr_in_t *address, socklen_t address_len);
int listen(int socket, int backlog);
int setsockopt(int socket, int level, int option_name, const void *option_value,
               socklen_t option_len);
int fork(void);
NORETURN void exit(int status);
#else

// clang -Oz will use push 1 / pop rax (3 bytes)
// push imm8/pop/syscall is the same size as call rel32
// syscalls don't destory their input regs, so inlining lets the compiler avoid save/restore
// and lets the compiler use call-clobbered regs for everything, which means less R12-R15, fewer REX prefixes
#include <asm/unistd.h>
ALWAYS_INLINE NORETURN static inline void exit(int status) {
  __asm__ volatile("syscall" :: "a"(__NR_exit), "D"(status) );
  // would normally clobber RCX and R11, but we're exiting anyway
  __builtin_unreachable();
}

static inline ssize_t read(int fd, void *buf, size_t nbyte){
  ssize_t retval;
  __asm__ volatile("syscall"
		   : "=a"(retval), "=m"(*(char (*)[nbyte]) buf)  // output buffer
		   : "a"(__NR_read), "D"(fd), "S"(buf), "d"(nbyte)
		   : "rcx", "r11");
  return retval;
}
static inline ssize_t write(int fd, void *buf, size_t nbyte){
  ssize_t retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_write), "D"(fd), "S"(buf), "d"(nbyte),
		     "m"(*(const char (*)[nbyte]) buf) // input buffer dummy operand instead of "memory" clobber
		   : "rcx", "r11");
  return retval;
}

static inline int open(const char *path, int flags){
  int retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_open), "D"(path), "S"(flags),
		     "m"(*(const char (*)[16]) path)  // clang doesn't like [], 16 is probably safe enough, and there aren't stores to the path buffer that could be seen as dead anyway.
		   : "rcx", "r11");
  return retval;
}
static inline int close(int fd){
  int retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_close), "D"(fd)
		   : "rcx", "r11");
  return retval;
}
static inline int socket(int domain, int type, int protocol){
  int retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_socket), "D"(domain), "S"(type), "d"(protocol)
		   : "rcx", "r11");
  return retval;
}
static inline int accept(int socket, sockaddr_in_t *restrict address,
           socklen_t *restrict address_len) {
  int retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_accept), "D"(socket), "S"(address), "d"(address_len)
		   : "rcx", "r11", "memory");  // just clobber mem instead of being specific
  return retval;
}
static inline int shutdown(int socket, int how){
  int retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_shutdown), "D"(socket), "S"(how)
		   : "rcx", "r11");
  return retval;
}
static inline int bind(int socket, const sockaddr_in_t *address, socklen_t address_len){
  ssize_t retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_bind), "D"(socket), "S"(address), "d"(address_len)
		     , "m"(*(const char (*)[address_len]) address)  // length is in bytes
		   : "rcx", "r11");
  return retval;
}
static inline int listen(int socket, int backlog){
  int retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_listen), "D"(socket), "S"(backlog)
		   : "rcx", "r11");
  return retval;
}
static inline int setsockopt(int socket, int level, int option_name, const void *option_value,
               socklen_t option_len) {
  int retval;
  register const void *optval_r10 __asm__("r10") = option_value;
  register socklen_t optlen_r8 __asm__("r8") = option_len;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_setsockopt), "D"(socket), "S"(level), "d"(option_name),
		     "r"(optval_r10), "r"(optlen_r8)
		     , "m"(*(const char (*)[option_len]) option_value)
		   : "rcx", "r11");
  return retval;
}

static inline int fork(void){
  int retval;
  __asm__ volatile("syscall"
		   : "=a"(retval)
		   : "a"(__NR_fork)
		   : "rcx", "r11");
  return retval;
}
#endif

#if 1    // unused if we hardcode "httpd" instead of argv[0]
//inline makes it ok for it to be unused: compiler will just omit a definition
inline size_t strlen(const char *s) {
  const char *p = s;
  while (*p)
    ++p;
  return p - s;
}
#endif

static uint16_t swap_uint16(uint16_t x) {
  return (((x << 8) & 0xFF00) | ((x >> 8) & 0x00FF));
}

#define fprint(fd, s) write(fd, s, strlen(s))

#define fprintn(fd, s, n) write(fd, s, n)

#define fprintl(fd, s) fprintn(fd, s, sizeof(s) - 1)

#define fprintln(fd, s) fprintl(fd, s "\n")

#define print(s) fprint(1, s)

#define printn(s, n) fprintn(1, s, n)

#define printl(s) fprintl(1, s)

#define println(s) fprintln(1, s)

#ifdef DEBUG
#define die(s)                                                                 \
  println("FATAL: " s);                                                        \
  exit(1)

#define perror(s) println("ERROR: " s)
#else
#define die(s) exit(1)

#define perror(s)
#endif

static
int tcp_listen(const sockaddr_in_t *addr, const void *option_value,
               socklen_t option_len) {
  int sock;
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0 ||
      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, option_value, option_len) ||
      bind(sock, addr, sizeof(sockaddr_in_t)) || listen(sock, 10)) {
    die("listen");
  }
  return sock;
}

static void http_consume(int clientfd, char *http_buf, size_t buf_len) {
  int n;   // long (pointer width) avoids a movsxd, but telling the compiler about read's true return width costs other REX prefixes
  while ((n = read(clientfd, http_buf, buf_len)) > 0) {
    printn(http_buf, n);
    const char *p = http_buf + (n - 3);
    if (n < 3 || (*p == '\n' && *(p + 1) == '\r' && *(p + 2) == '\n')) {
      return;
    }
  }
  if (n < 0) {
    perror("read");
  }
}

static void http_drop(int clientfd) {
  shutdown(clientfd, SHUT_RDWR);
  close(clientfd);
}

/*
 * we're supposed to send content-length but shutting down the
 * socket seems to be enough, saves some code
 *
 * a http server is usually expected to respond to HEAD
 * requests without sending the actual content, we're not gonna
 * do that just to keep it tiny
 *
 * also, we could cache the file in memory instead of opening
 * it every time but since this is an exercise in making tiny
 * binaries it also makes sense to keep the mem usage low
 */

#define http_code(fd, x) fprintl(fd, "HTTP/1.1 " x "\r\n\r\n" x);

ALWAYS_INLINE
static int http_serve(int clientfd, const char *file_path, char *http_buf,
                      size_t buf_len) {
  int f, n;
  http_consume(clientfd, http_buf, buf_len);
  if ((f = open(file_path, O_RDONLY)) < 0) {
    perror("open");
    http_code(clientfd, "404 Not Found");
    return 1;
  }
  fprintl(clientfd, "HTTP/1.1 200 OK\r\n\r\n");
  while ((n = read(f, http_buf, buf_len)) > 0) {
    if (write(clientfd, http_buf, n) < 0) {
      perror("write");
      return 1;
    }
  }
  if (n < 0) {
    perror("read");
  }
  http_drop(clientfd);
  return 0;
}

static uint32_t string2port(const char *s) {
	//const unsigned char *s = (const unsigned char*)s_plain;  // lets GCC use movzx, but no code-size benefit
	uint32_t res = 0;   // uint16_t was causing a missed optimization: movsx word, byte [mem] instead of dword, costing an operand-size prefix.
#if 0
  for (; *s; ++s) {
    if (*s > '9' || *s < '0') {
      return 0;
    }
    res = res * 10 + *s - '0';
  }
#else
  for (; *s <= '9' && *s >= '0'; ++s) {
    res = res * 10 + *s - '0';
  }
//  if (*s != '\0') return 0;  // return 0 instead of 123 on strings like 123xyz
  // with this check uncommented, the other way is smaller
#endif
  return swap_uint16(res);
}

NORETURN static inline void usage(const char *self) {
#if 0
  printl("usage: ");
  print(self);
  println(" port file");
#else
  println("usage: httpd port file");
#endif
  exit(1);
}

int main(int argc, char *argv[]) {
  int sock;
  uint32_t port;
  char http_buf[8192];
  if (argc != 3 || (port = string2port(argv[1])) == 0) {
    usage(argv[0]);
  }
  const int yes = 1;
  const sockaddr_in_t addr = {AF_INET, port, 0};
  sock = tcp_listen(&addr, &yes, sizeof(yes));
  while (1) {
    int pid, clientfd;
    if ((clientfd = accept(sock, 0, 0)) < 0) {
      perror("accept");
    } else if ((pid = fork()) < 0) {
      perror("fork");
    } else if (pid == 0) {
	exit (http_serve(clientfd, argv[2], http_buf, sizeof(http_buf)));
    }
  }
  exit(0);
  return 0;
}
