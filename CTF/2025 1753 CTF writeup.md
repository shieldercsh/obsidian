I didn't solve the first two problems because they seemed too easy.(and they have many solver.)

1. data_saver

---
# data_saver

```bash
[*] '/mnt/d/1753ctf/Data saver/data_saver'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

Partial RELRO

```C
int main() {
        save_file = fopen("save.dat", "ab+");
        uint8_t message[1500];
        while (true) {
                ssize_t bytes_read = read(STDIN_FILENO, message, 1500);
                if (bytes_read == 0 || bytes_read == -1) {
                        break;
                }
                process_message(message, save_file);
        }
	fclose(save_file);
}
```

