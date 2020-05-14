![atx logo](https://github.com/ImanHosseini/AtX/raw/master/atx_c.png "AtX")
## Translating ARM to X86
I am trying to answer how hard it would be to translate an _ARM32_ elf binary to a _X86\_64_ elf binary. This is meant as a course project to _The Art of Embedded Exploitation_ course \[Spring 2020\] taught by Stephen A. Ridley at NYU. The idea was to be able to do this for simple _ARM32_ binaries, and I started by trying to port one of the simple stack smashing binaries by hand, and then trying to make it 'automated'. I had previous experience with ARM architecture, from my undergrad thesis [JAA](https://github.com/ImanHosseini/JAA) which was something similar, but for translating JVM bytecode to ARM. The tools I picked for doing this are [Capstone Engine](http://www.capstone-engine.org/) for disassembly, [LIEF](https://lief.quarkslab.com/) to fiddle with elf headers and decided on [NASM- Netwide Assembler](https://nasm.us/) for output: so that my _translator_ generates assembly that then _NASM_ would assemble into an X86_64 binary.

## Some thoughts
Based on the function calling conventions for the ABIs, I decided on a mapping of registers: 

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

This way, function calls _can_ become seamless, i.e. first arg is passed on R0 in ARM32, becomes DI in X86_64. Also for the stack, let's just mimic the same stack: anything pushed in ARM, push it in x86. Issues arise regarding how to handle data section and pc-relative addressings: in ARM, the mechanism is via the link-register and you can just pop stuff from stack to lr, in x86 this is not the case with _RIP_ and instead _CALL_ and _RET_ are used (rather than _BL_ and _mov PC, LR_). 

There are small differences like how ARM arithmetic instructions have 3 operand (unlike x86 which has 2, the 1st also acting as destination) which can be rather easily handled: for "ADD Rd, Rx, Ry" generate "MOV Rd, Rx", "ADD Rd, Ry", or like how in ARM any instruction can get executed _conditionaly_. Like how you have ADD, and then ADDNE -NE for Not Equal- which does an ADD **IF** NE, and NE can be any condition [code](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0204j/Chdhcfbc.html). Also there are issues which are harder to handle, like the issue with pc-relative addressing. 

I am not picky though, it's a fun limited project, I am not thinking through everything, like how to do this *provably correct* like, there are so many edge cases on everything, even simple arithmetics are really not _same_ due to different _imm_ widths and such and such. My simple _model_ for this is that I am essentialy making an equivalence between the state of the system in each arch; call it f(S) which maps a state S from the ARM machine to an state in x86 machine , and I assume that for each ARM instruction, taking the ARM system from state S->S' there exists a sequence of x86 instructions which take f(S) to f(S').
