![atx logo](https://github.com/ImanHosseini/AtX/raw/master/atx_c.png "AtX")
# Translating ARM to X86
I was trying to answer how hard it would be to translate an _ARM32_ elf binary to a _X86\_64_ elf binary. First, based on the function calling conventions for the ABIs, I decided on a mapping of registers: 

| ARM32         | X86_64        |
| ------------- |:-------------:|
| R0 | EDI |
| R1 | ESI |
| R2 | EDX |
| R3 | ECX |
| R4 | EAX |
| R5 | EBX |
| R6 | R8d |
| R7 | R9d |
| R8 | R10d|
| R9 | R11d|
| R10| R12d|
| R11| R13d|
| R12| R14d|
| LR | R15 |
| SP | RSP |

This way, function calls _can_ become seamless, i.e. first arg is passed on R0 in ARM32, becomes DI in X86_64. 
