# Local & Remote Buffer Overflow

A buffer overflow occurs when a program writes more data to a buffer than it can hold. Since buffers are allocated with a finite size, exceeding this limit can overwrite adjacent memory, leading to potentially exploitable vulnerabilities. Attackers can leverage buffer overflows to manipulate a program's execution flow, often aiming to execute arbitrary code.

## Disclaimer

The tools and scripts provided in this repository are made available for educational purposes only and are intended to be used for testing and protecting systems with the consent of the owners. The author does not take any responsibility for the misuse of these tools. It is the end user's responsibility to obey all applicable local, state, national, and international laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Under no circumstances should this tool be used for malicious purposes. The author of this tool advocates for the responsible and ethical use of security tools. Please use this tool responsibly and ethically, ensuring that you have proper authorization before engaging any system with the techniques demonstrated by this project.

## Features

This project demonstrates exploiting a buffer overflow vulnerability in a binary compiled with an executable stack (`"./executable_stack"`). The Python script combines initial analysis (with GDB - GNU Debugger), dynamic user input for flexibility, and the automatic generation and delivery of an exploit payload. It is designed to work both locally and remotely, offering flexibility in testing and exploitation scenarios.

## Prerequisites

- **Operating System**: Tested on Kali Linux 2023.4
- **Python Version**: Python 3.6+
- **pwntools**: A powerful library for writing exploits, used extensively in this script for managing connections, processes, and crafting payloads.
- **247CTF.com**: Access to remote linux machine hosted on https://247ctf.com/dashboard under Challenges Pwnable > An Executable Stack.
 
## Installation

1. **Python Environment Setup**: Ensure Python and pip are installed. Install the required libraries using:
    
    ```bash
    pip install pwntools
    ```
    
2. **Download Scripts**: Clone or download the scripts from the project repository to your local machine.
3. **Download the Required Binary**: Follow the usage instructions to download the `executable_stack` binary which is necessary for running the script.

## Usage

1. **Prepare the Binary**: 
    - Create a free account with https://247ctf.com/dashboard then login.
    - Navigate to `CHALLENGES PWNABLE` > `AN EXECUTABLE STACK`.
    - Click `DOWNLOAD CHALLENGE` to download the `executable_stack` binary file.
    - Click `START CHALLENGE` to start the remote target host.
    - After downloading the `executable_stack` binary, ensure it is executable: `chmod +x executable_stack`
2. **Uncomment Necessary Code Sections**: Uncomment the sections in the script that generate and send a cyclic pattern to the application. This is done to determine where the program crashes.
3. **Run the Script**: Follow the prompts to start either a local or a remote process.
    
    ```bash
    python3 buffer_overflow.py
    ```
    
4. **Observe and Record the Fault Address**: Run locally to catch the crash with GDB and observe the fault address directly from the debugger output.
5. **Comment Out the Cyclic Pattern Code**: Once you have the fault address, comment out the code block that sends the cyclic pattern and pauses the script. You no longer need to send the cyclic pattern as you will be crafting a targeted exploit based on the fault address obtained.
6. **Input the Fault Address**: Run the script with the local option and enter the fault address as requested.
7. **Craft and Send Exploit**: With the fault address known, the script should now build the payload that includes the exact buffer overflow offset, control transfer instructions (`jmp esp`), and your shellcode.
8. **Remote Execution**: Run the script after obtaining the fault address and select the remote option to proceed with remote execution.

## How It Works

- **Setting Up the Environment:** The script starts by setting the execution context to a 32-bit Linux architecture, which is crucial for ensuring that the payload matches the target environment.
- **Binary Loading:** The vulnerable binary (`"./executable_stack"`) is loaded using `pwntools`, which allows for interaction and exploitation.
- **Process Selection:** The script prompts the user to choose between running a local instance of the binary or connecting to a remote service hosting the binary. This flexibility facilitates both local testing and remote exploitation.
- **Debugging and Offset Finding:** Initially, you would uncomment the indicated code sections to attach GDB for debugging, send a cyclic pattern to the process, and identify the offset at which the segmentation fault occurs. This offset indicates where the instruction pointer can be controlled.
- **Fault Address Input:** After determining the fault address where the buffer overflow occurs, the script prompts for this address. This is a key step in transitioning from identifying the vulnerability to exploiting it.
- **Offset Calculation:** Using the fault address provided by the user, `cyclic_find()` calculates the precise offset needed to overwrite the instruction pointer.
- **Finding `jmp esp` Address:** The script searches the binary for a `jmp esp` instruction, which is essential for redirecting execution flow to the stack, where the shellcode resides.
- **Payload Construction:** An exploit payload is constructed with a precise amount of padding up to the offset, followed by the `jmp esp` address and the shellcode generated by `pwntools`' `shellcraft`. The payload is explicitly handled in byte format to avoid issues with text encoding.
- **Payload Delivery:** Finally, the script sends the crafted exploit payload to the vulnerable binary and switches to interactive mode, allowing the attacker to interact with the spawned shell or manipulated program execution.

## Output Example

**Target: Local Host (executable_stack)**

**GDB (GNU Debugger)**

```bash
Reading symbols from /home/kali/Documents/executable_stack...
(No debugging symbols found in /home/kali/Documents/executable_stack)
Attaching to program: /home/kali/Documents/executable_stack, process 57996
Reading symbols from /lib32/libc.so.6...
(No debugging symbols found in /lib32/libc.so.6)
Reading symbols from /lib/ld-linux.so.2...
(No debugging symbols found in /lib/ld-linux.so.2)
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0xf7f79579 in __kernel_vsyscall ()

Program received signal SIGSEGV, Segmentation fault.
0x6261616b in ?? ()
(gdb) i r
eax            0xffe05d50          -2073264
ecx            0xf7e1f9c4          -136185404
edx            0x0                 0
ebx            0x62616169          1650549097
esp            0xffe05de0          0xffe05de0
ebp            0x6261616a          0x6261616a
esi            0x8048540           134513984
edi            0xf7fadba0          -134554720
eip            0x6261616b          0x6261616b
eflags         0x10286             [ PF SF IF RF ]
cs             0x23                35
ss             0x2b                43
ds             0x2b                43
es             0x2b                43
fs             0x0                 0
gs             0x63                99
```

```bash
[*] '/home/kali/Documents/executable_stack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
Run [local] process or [remote] connection? local
[+] Starting local process '/home/kali/Documents/executable_stack': pid 59113
Enter the fault address in hexadecimal format (e.g., 0x6261616b): 0x6261616b
Address of jmp esp: 0x80484b3
[*] Switching to interactive mode
There are no flag functions here!
You can try to make your own though:
$
```

**Target: Remote Host @ `tcp://8e001fc4700cecd1.247ctf.com:50113`**

```bash
[*] '/home/kali/Documents/executable_stack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
Run [local] process or [remote] connection? remote
Enter the full remote address (format tcp://host:port): tcp://8e001fc4700cecd1.247ctf.com:50113
[+] Opening connection to 8e001fc4700cecd1.247ctf.com on port 50113: Done
Enter the fault address in hexadecimal format (e.g., 0x6261616b): 0x6261616b
Address of jmp esp: 0x80484b3
[*] Switching to interactive mode
There are no flag functions here!
You can try to make your own though:
$ ls
chall
flag_27886b9a498ed936.txt
$ tail flag_27886b9a498ed936.txt
247CTF{27886b9a498ed93685af9db0b1e304ec}
```

## Contributing

If you have an idea for an improvement or if you're interested in collaborating, you are welcome to contribute. Please feel free to open an issue or submit a pull request.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
