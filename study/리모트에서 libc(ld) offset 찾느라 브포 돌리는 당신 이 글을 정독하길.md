pwn을 하면서 `libc` 주소를 알아내고 `ld` 영역을 overwrite해야 하는 경우가 심심치 않게 있다. 그럴 때마다 로컬과 리모트의 `libc, ld` offset이 달라서 `i * 0x1000`으로 브포를 돌리는 것이 인텐으로 자리 잡고 있다. 나의 경우 c++ binary 익스에서 exit handler overwrite를 하는데 브포를 돌려도 익스가 안 되는 것이다. 그래서 한참 헤매다가 이 방법을 발견하고 offset을 확인해보니 꽤 멀리 떨어져 있었다. 방법을 소개하겠다.

- 준비물 : Dockerfile

1. docker에서 `ls /proc`을 친다.
2. `nc localhost {port}`를 실행한 후 `ls /proc`을 쳐서 1번에서 없던 pid를 찾는다.
3. `cat /proc/{pid}/maps`를 하면 `lib` 주소들이 나와서 우리가 찾던 offset을 모두 계산할 수 있다.

아래는 내 도커에서 그대로 실행한 로그이다.

```bash
/srv # ls /proc
1             cgroups       devices       fs            kcore         kpageflags    modules       schedstat     sysvipc       vmallocinfo
11            cmdline       diskstats     interrupts    key-users     loadavg       mounts        self          thread-self   vmstat
26            config.gz     dma           iomem         keys          locks         mtrr          softirqs      timer_list    zoneinfo
acpi          consoles      driver        ioports       kmsg          mdstat        net           stat          tty
buddyinfo     cpuinfo       execdomains   irq           kpagecgroup   meminfo       pagetypeinfo  swaps         uptime
bus           crypto        filesystems   kallsyms      kpagecount    misc          partitions    sys           version
/srv # ls /proc
1             bus           crypto        filesystems   kallsyms      kpagecount    misc          partitions    sys           version
11            cgroups       devices       fs            kcore         kpageflags    modules       schedstat     sysvipc       vmallocinfo
27            cmdline       diskstats     interrupts    key-users     loadavg       mounts        self          thread-self   vmstat
28            config.gz     dma           iomem         keys          locks         mtrr          softirqs      timer_list    zoneinfo
acpi          consoles      driver        ioports       kmsg          mdstat        net           stat          tty
buddyinfo     cpuinfo       execdomains   irq           kpagecgroup   meminfo       pagetypeinfo  swaps         uptime
/srv # ls /proc/27/maps
/proc/27/maps
/srv # cat /proc/27/maps
55f8e8e67000-55f8e8e68000 r--p 00000000 08:40 506735                     /app/run
55f8e8e68000-55f8e8e69000 r-xp 00001000 08:40 506735                     /app/run
55f8e8e69000-55f8e8e6a000 r--p 00002000 08:40 506735                     /app/run
55f8e8e6a000-55f8e8e6b000 r--p 00002000 08:40 506735                     /app/run
55f8e8e6b000-55f8e8e6c000 rw-p 00003000 08:40 506735                     /app/run
7f02939d1000-7f02939d4000 rw-p 00000000 00:00 0 
7f02939d4000-7f02939fc000 r--p 00000000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f02939fc000-7f0293b84000 r-xp 00028000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293b84000-7f0293bd3000 r--p 001b0000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293bd3000-7f0293bd7000 r--p 001fe000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293bd7000-7f0293bd9000 rw-p 00202000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293bd9000-7f0293be6000 rw-p 00000000 00:00 0 
7f0293be8000-7f0293bea000 rw-p 00000000 00:00 0 
7f0293bea000-7f0293beb000 r--p 00000000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293beb000-7f0293c16000 r-xp 00001000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293c16000-7f0293c20000 r--p 0002c000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293c20000-7f0293c22000 r--p 00036000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293c22000-7f0293c24000 rw-p 00038000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffd00519000-7ffd0053a000 rw-p 00000000 00:00 0                          [stack]
7ffd0057a000-7ffd0057e000 r--p 00000000 00:00 0                          [vvar]
7ffd0057e000-7ffd00580000 r-xp 00000000 00:00 0                          [vdso]
/srv # cat /proc/28/maps
cat: can't open '/proc/28/maps': No such file or directory
/srv # cat /proc/27/maps
55f8e8e67000-55f8e8e68000 r--p 00000000 08:40 506735                     /app/run
55f8e8e68000-55f8e8e69000 r-xp 00001000 08:40 506735                     /app/run
55f8e8e69000-55f8e8e6a000 r--p 00002000 08:40 506735                     /app/run
55f8e8e6a000-55f8e8e6b000 r--p 00002000 08:40 506735                     /app/run
55f8e8e6b000-55f8e8e6c000 rw-p 00003000 08:40 506735                     /app/run
7f02939d1000-7f02939d4000 rw-p 00000000 00:00 0 
7f02939d4000-7f02939fc000 r--p 00000000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f02939fc000-7f0293b84000 r-xp 00028000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293b84000-7f0293bd3000 r--p 001b0000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293bd3000-7f0293bd7000 r--p 001fe000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293bd7000-7f0293bd9000 rw-p 00202000 08:40 507618                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f0293bd9000-7f0293be6000 rw-p 00000000 00:00 0 
7f0293be8000-7f0293bea000 rw-p 00000000 00:00 0 
7f0293bea000-7f0293beb000 r--p 00000000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293beb000-7f0293c16000 r-xp 00001000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293c16000-7f0293c20000 r--p 0002c000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293c20000-7f0293c22000 r--p 00036000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f0293c22000-7f0293c24000 rw-p 00038000 08:40 507598                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffd00519000-7ffd0053a000 rw-p 00000000 00:00 0                          [stack]
7ffd0057a000-7ffd0057e000 r--p 00000000 00:00 0                          [vvar]
7ffd0057e000-7ffd00580000 r-xp 00000000 00:00 0                          [vdso]
/srv #
```

이 글을 읽는 포너들은 앞으로 브포하지 말고 도커에서 한 번에 offset을 구하길 바란다.