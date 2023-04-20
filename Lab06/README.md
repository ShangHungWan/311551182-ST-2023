# Lab06

## Overview

|      |   Valgrind   |  ASAN    |
| ---- | ---- | ---- |
|  Heap out-of-bounds    |   O   |   X   |
|  Stack out-of-bounds    |   X   |   O   |
|  Global Heap out-of-bounds    |   X   |   O   |
|  Use-after-free    |   O   |    X  |
|  Use-after-return    |   X   |   O   |

## Environments

- GCC 12.2.1
- Valgrind 3.20.0

## Test cases

### Skip Redzone

Run:

```bash
gcc -fsanitize=address -O1 -g asan_buffer_overflow.c
./a.out
```

Please refer to `asan_buffer_overflow.c`.

When skip red-zone and keep it remain unchanged, ASan cannot monitor the buffer overflow problem.

### Heap out-of-bounds

- ASan X
- Valgrind O

#### Code

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    char *x = (char *)malloc(2 * sizeof(char));
    x[2] = 'A';
    printf("%c\n", x[2]);

    return 0;
}
```

#### ASan

```
A
```

#### Valgrind

```
==4972== Memcheck, a memory error detector
==4972== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==4972== Using Valgrind-3.20.0 and LibVEX; rerun with -h for copyright info
==4972== Command: ./a.out
==4972== 
==4972== Invalid write of size 1
==4972==    at 0x401154: main (in /home/sun/311551182-ST-2023/Lab06/a.out)
==4972==  Address 0x4a48042 is 0 bytes after a block of size 2 alloc'd
==4972==    at 0x484386F: malloc (vg_replace_malloc.c:393)
==4972==    by 0x401147: main (in /home/sun/311551182-ST-2023/Lab06/a.out)
==4972== 
==4972== Invalid read of size 1
==4972==    at 0x40115F: main (in /home/sun/311551182-ST-2023/Lab06/a.out)
==4972==  Address 0x4a48042 is 0 bytes after a block of size 2 alloc'd
==4972==    at 0x484386F: malloc (vg_replace_malloc.c:393)
==4972==    by 0x401147: main (in /home/sun/311551182-ST-2023/Lab06/a.out)
==4972== 
A
==4972== 
==4972== HEAP SUMMARY:
==4972==     in use at exit: 2 bytes in 1 blocks
==4972==   total heap usage: 2 allocs, 1 frees, 1,026 bytes allocated
==4972== 
==4972== LEAK SUMMARY:
==4972==    definitely lost: 2 bytes in 1 blocks
==4972==    indirectly lost: 0 bytes in 0 blocks
==4972==      possibly lost: 0 bytes in 0 blocks
==4972==    still reachable: 0 bytes in 0 blocks
==4972==         suppressed: 0 bytes in 0 blocks
==4972== Rerun with --leak-check=full to see details of leaked memory
==4972== 
==4972== For lists of detected and suppressed errors, rerun with: -s
==4972== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 0 from 0)
```

### Stack out-of-bounds

- ASan O
- Valgrind X

#### Code

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
    char x[2];
    x[2] = 'A';
    printf("%c\n", x[2]);

    return 0;
}
```

#### ASan

```
=================================================================
==6626==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffce59ba802 at pc 0x000000401248 bp 0x7ffce59ba7d0 sp 0x7ffce59ba7c8
WRITE of size 1 at 0x7ffce59ba802 thread T0
    #0 0x401247 in main /home/sun/311551182-ST-2023/Lab06/stack_out_of_bound.c:7
    #1 0x7f24ad84a50f in __libc_start_call_main (/lib64/libc.so.6+0x2750f)
    #2 0x7f24ad84a5c8 in __libc_start_main@GLIBC_2.2.5 (/lib64/libc.so.6+0x275c8)
    #3 0x4010c4 in _start (/home/sun/311551182-ST-2023/Lab06/a.out+0x4010c4)

Address 0x7ffce59ba802 is located in stack of thread T0 at offset 34 in frame
    #0 0x401195 in main /home/sun/311551182-ST-2023/Lab06/stack_out_of_bound.c:5

  This frame has 1 object(s):
    [32, 34) 'x' (line 6) <== Memory access at offset 34 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /home/sun/311551182-ST-2023/Lab06/stack_out_of_bound.c:7 in main
Shadow bytes around the buggy address:
  0x10001cb2f4b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f4c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f4d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f4e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f4f0: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1
=>0x10001cb2f500:[02]f3 f3 f3 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f510: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f520: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f530: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10001cb2f550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==6626==ABORTING
```

#### Valgrind

```
==6388== Memcheck, a memory error detector
==6388== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==6388== Using Valgrind-3.20.0 and LibVEX; rerun with -h for copyright info
==6388== Command: ./a.out
==6388== 
A
==6388== 
==6388== HEAP SUMMARY:
==6388==     in use at exit: 0 bytes in 0 blocks
==6388==   total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==6388== 
==6388== All heap blocks were freed -- no leaks are possible
==6388== 
==6388== For lists of detected and suppressed errors, rerun with: -s
==6388== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

### Global out-of-bounds

- ASan O
- Valgrind X

#### Code

```c
#include <stdlib.h>
#include <stdio.h>

char x[2];

int main()
{
    x[2] = 'A';
    printf("%c\n", x[2]);

    return 0;
}
```

#### ASan

```
=================================================================
==7704==ERROR: AddressSanitizer: global-buffer-overflow on address 0x000000404142 at pc 0x0000004011c7 bp 0x7ffc6beada10 sp 0x7ffc6beada08
WRITE of size 1 at 0x000000404142 thread T0
    #0 0x4011c6 in main /home/sun/311551182-ST-2023/Lab06/global_out_of_bound.c:8
    #1 0x7f720304a50f in __libc_start_call_main (/lib64/libc.so.6+0x2750f)
    #2 0x7f720304a5c8 in __libc_start_main@GLIBC_2.2.5 (/lib64/libc.so.6+0x275c8)
    #3 0x4010b4 in _start (/home/sun/311551182-ST-2023/Lab06/a.out+0x4010b4)

0x000000404142 is located 0 bytes to the right of global variable 'x' defined in 'global_out_of_bound.c:4:6' (0x404140) of size 2
SUMMARY: AddressSanitizer: global-buffer-overflow /home/sun/311551182-ST-2023/Lab06/global_out_of_bound.c:8 in main
Shadow bytes around the buggy address:
  0x0000800787d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800787e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0000800787f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080078800: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080078810: 00 00 00 00 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
=>0x000080078820: f9 f9 f9 f9 00 00 00 00[02]f9 f9 f9 f9 f9 f9 f9
  0x000080078830: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080078840: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080078850: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080078860: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080078870: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==7704==ABORTING
```

#### Valgrind

```
==7607== Memcheck, a memory error detector
==7607== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==7607== Using Valgrind-3.20.0 and LibVEX; rerun with -h for copyright info
==7607== Command: ./a.out
==7607== 
A
==7607== 
==7607== HEAP SUMMARY:
==7607==     in use at exit: 0 bytes in 0 blocks
==7607==   total heap usage: 1 allocs, 1 frees, 1,024 bytes allocated
==7607== 
==7607== All heap blocks were freed -- no leaks are possible
==7607== 
==7607== For lists of detected and suppressed errors, rerun with: -s
==7607== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

### Use-after-free

- ASan X
- Valgrind O

#### Code

```c
#include <stdlib.h>

int main()
{
    char *x = (char *)malloc(2 * sizeof(char));
    free(x);
    x[1] = 'A';

    return 0;
}
```

#### ASan

N/A

#### Valgrind

```
==8213== Memcheck, a memory error detector
==8213== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==8213== Using Valgrind-3.20.0 and LibVEX; rerun with -h for copyright info
==8213== Command: ./a.out
==8213== 
==8213== Invalid write of size 1
==8213==    at 0x401160: main (in /home/sun/311551182-ST-2023/Lab06/a.out)
==8213==  Address 0x4a48041 is 1 bytes inside a block of size 2 free'd
==8213==    at 0x48460E4: free (vg_replace_malloc.c:884)
==8213==    by 0x401157: main (in /home/sun/311551182-ST-2023/Lab06/a.out)
==8213==  Block was alloc'd at
==8213==    at 0x484386F: malloc (vg_replace_malloc.c:393)
==8213==    by 0x401147: main (in /home/sun/311551182-ST-2023/Lab06/a.out)
==8213== 
==8213== 
==8213== HEAP SUMMARY:
==8213==     in use at exit: 0 bytes in 0 blocks
==8213==   total heap usage: 1 allocs, 1 frees, 2 bytes allocated
==8213== 
==8213== All heap blocks were freed -- no leaks are possible
==8213== 
==8213== For lists of detected and suppressed errors, rerun with: -s
==8213== ERROR SUMMARY: 1 errors from 1 contexts (suppressed: 0 from 0)
```

### Use-after-return

- ASan O
- Valgrind X

#### Code

```c
char *x;

void foo()
{
    char buffer[2];
    x = &buffer[1];
}

int main()
{

    foo();
    *x = 42;

    return 0;
}

```

#### ASan

```
=================================================================
==10478==ERROR: AddressSanitizer: stack-use-after-scope on address 0x7fffa42b1711 at pc 0x0000004012d5 bp 0x7fffa42b16e0 sp 0x7fffa42b16d8
WRITE of size 1 at 0x7fffa42b1711 thread T0
    #0 0x4012d4 in main /home/sun/311551182-ST-2023/Lab06/use_after_return.c:13
    #1 0x7eff3744a50f in __libc_start_call_main (/lib64/libc.so.6+0x2750f)
    #2 0x7eff3744a5c8 in __libc_start_main@GLIBC_2.2.5 (/lib64/libc.so.6+0x275c8)
    #3 0x4010b4 in _start (/home/sun/311551182-ST-2023/Lab06/a.out+0x4010b4)

Address 0x7fffa42b1711 is located in stack of thread T0 at offset 33 in frame
    #0 0x401222 in main /home/sun/311551182-ST-2023/Lab06/use_after_return.c:10

  This frame has 1 object(s):
    [32, 34) 'buffer' (line 5) <== Memory access at offset 33 is inside this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-use-after-scope /home/sun/311551182-ST-2023/Lab06/use_after_return.c:13 in main
Shadow bytes around the buggy address:
  0x10007484e290: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e2a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e2b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e2c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e2d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1
=>0x10007484e2e0: f1 f1[f8]f3 f3 f3 00 00 00 00 00 00 00 00 00 00
  0x10007484e2f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e300: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e310: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e320: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x10007484e330: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==10478==ABORTING
```

#### Valgrind

```
==10571== Memcheck, a memory error detector
==10571== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==10571== Using Valgrind-3.20.0 and LibVEX; rerun with -h for copyright info
==10571== Command: ./a.out
==10571== 
==10571== 
==10571== HEAP SUMMARY:
==10571==     in use at exit: 0 bytes in 0 blocks
==10571==   total heap usage: 0 allocs, 0 frees, 0 bytes allocated
==10571== 
==10571== All heap blocks were freed -- no leaks are possible
==10571== 
==10571== For lists of detected and suppressed errors, rerun with: -s
==10571== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```
