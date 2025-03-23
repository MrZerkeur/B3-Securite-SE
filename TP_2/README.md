# TP2 : Syscalls

## Part I : Learn

### 1. Anatomy of a program

#### A. file

🌞 **Utiliser file pour déterminer le type de :**

```
[axel@TP2-Secu-SE ~]$ file /usr/bin/ls
/usr/bin/ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1afdd52081d4b8b631f2986e26e69e0b275e159c, for GNU/Linux 3.2.0, stripped

[axel@TP2-Secu-SE ~]$ file /usr/sbin/ip
/usr/sbin/ip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=77a2f5899f0529f27d87bb29c6b84c535739e1c7, for GNU/Linux 3.2.0, stripped

[axel@TP2-Secu-SE ~]$ file quiz-blind-test-187140.mp3 
quiz-blind-test-187140.mp3: MPEG ADTS, layer III, v1, 256 kbps, 44.1 kHz, JntStereo
```

Résumé :
```
ls : ELF
ip : ELF
.mp3 : MPEG
```

#### B. readelf

🌞 **Utiliser readelf sur le programme ls**

```
[axel@TP2-Secu-SE ~]$ readelf -S /usr/bin/ls | grep -A 1 .text
  [15] .text             PROGBITS         0000000000004d50  00004d50
       0000000000012532  0000000000000000  AX       0     0     16
```

#### C. ldd

🌞 **Utiliser ldd sur le programme ls**

```
[axel@TP2-Secu-SE ~]$ ldd /usr/bin/ls
	linux-vdso.so.1 (0x00007ffc603fc000)
	libselinux.so.1 => /lib64/libselinux.so.1 (0x00007f0188a58000)
	libcap.so.2 => /lib64/libcap.so.2 (0x00007f0188a4e000)
	libc.so.6 => /lib64/libc.so.6 (0x00007f0188800000)
	libpcre2-8.so.0 => /lib64/libpcre2-8.so.0 (0x00007f0188764000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f0188aaf000)
```

La Glibc est : libc.so.6 => /lib64/libc.so.6 (0x00007f0188800000)

### 2. Syscalls basics

#### A. Syscall list

🌞 **Donner le nom ET l'identifiant unique d'un syscall qui permet à un processus de...**

- lire un fichier stocké sur disque

read 0

- écrire dans un fichier stocké sur disque

write 1

- lancer un nouveau processus

execve 59

#### B. objdump

🌞 **Utiliser objdump sur la commande ls**

- afficher le contenu de la section .text

```objdump -M intel -d -j .text /usr/bin/ls```

- mettez en évidence quelques lignes qui contiennent l'instruction call

```
[axel@TP2-Secu-SE ~]$ objdump -M intel -d -j .text /usr/bin/ls | head -n 100 | grep -B 5 call

Disassembly of section .text:

0000000000004d50 <_obstack_begin@@Base-0xb090>:
    4d50:	50                   	push   rax
    4d51:	e8 da f9 ff ff       	call   4730 <abort@plt>
    4d56:	e8 d5 f9 ff ff       	call   4730 <abort@plt>
    4d5b:	e8 d0 f9 ff ff       	call   4730 <abort@plt>
    4d60:	e8 cb f9 ff ff       	call   4730 <abort@plt>
    4d65:	e8 c6 f9 ff ff       	call   4730 <abort@plt>
    4d6a:	e8 c1 f9 ff ff       	call   4730 <abort@plt>
    4d6f:	e8 bc f9 ff ff       	call   4730 <abort@plt>
    4d74:	e8 b7 f9 ff ff       	call   4730 <abort@plt>
    4d79:	e8 b2 f9 ff ff       	call   4730 <abort@plt>
--
    4da8:	0f 84 a6 1c 00 00    	je     6a54 <__sprintf_chk@plt+0x1d14>
    4dae:	41 89 fe             	mov    r14d,edi
    4db1:	48 89 f3             	mov    rbx,rsi
    4db4:	48 89 ef             	mov    rdi,rbp
    4db7:	be 2f 00 00 00       	mov    esi,0x2f
    4dbc:	e8 6f fb ff ff       	call   4930 <strrchr@plt>
--
    4dd3:	48 83 f8 06          	cmp    rax,0x6
    4dd7:	7e 3f                	jle    4e18 <__sprintf_chk@plt+0xd8>
    4dd9:	49 8d 7c 24 fa       	lea    rdi,[r12-0x6]
    4dde:	ba 07 00 00 00       	mov    edx,0x7
    4de3:	48 8d 35 ae 4e 01 00 	lea    rsi,[rip+0x14eae]        # 19c98 <_obstack_memory_used@@Base+0x9388>
    4dea:	e8 61 f9 ff ff       	call   4750 <strncmp@plt>
--
    4df1:	75 25                	jne    4e18 <__sprintf_chk@plt+0xd8>
    4df3:	ba 03 00 00 00       	mov    edx,0x3
    4df8:	48 8d 35 a1 4e 01 00 	lea    rsi,[rip+0x14ea1]        # 19ca0 <_obstack_memory_used@@Base+0x9390>
    4dff:	4c 89 ef             	mov    rdi,r13
    4e02:	4c 89 ed             	mov    rbp,r13
    4e05:	e8 46 f9 ff ff       	call   4750 <strncmp@plt>
--
    4e1f:	48 89 2d 32 d6 01 00 	mov    QWORD PTR [rip+0x1d632],rbp        # 22458 <obstack_alloc_failed_handler@@Base+0x3b8>
    4e26:	bf 06 00 00 00       	mov    edi,0x6
    4e2b:	48 8d 35 b6 4d 01 00 	lea    rsi,[rip+0x14db6]        # 19be8 <_obstack_memory_used@@Base+0x92d8>
    4e32:	48 89 28             	mov    QWORD PTR [rax],rbp
    4e35:	48 8d 2d 6a 4b 01 00 	lea    rbp,[rip+0x14b6a]        # 199a6 <_obstack_memory_used@@Base+0x9096>
    4e3c:	e8 1f fd ff ff       	call   4b60 <setlocale@plt>
    4e41:	48 8d 35 5c 4e 01 00 	lea    rsi,[rip+0x14e5c]        # 19ca4 <_obstack_memory_used@@Base+0x9394>
    4e48:	48 89 ef             	mov    rdi,rbp
    4e4b:	e8 20 fa ff ff       	call   4870 <bindtextdomain@plt>
    4e50:	48 89 ef             	mov    rdi,rbp
    4e53:	e8 d8 f9 ff ff       	call   4830 <textdomain@plt>
    4e58:	48 8d 3d b1 6c 00 00 	lea    rdi,[rip+0x6cb1]        # bb10 <__sprintf_chk@plt+0x6dd0>
    4e5f:	c7 05 17 d2 01 00 02 	mov    DWORD PTR [rip+0x1d217],0x2        # 22080 <_obstack_memory_used@@Base+0x11770>
    4e66:	00 00 00 
    4e69:	e8 02 24 01 00       	call   17270 <_obstack_memory_used@@Base+0x6960>
--
    4e95:	00 00 00 00 
    4e99:	48 89 05 b0 d8 01 00 	mov    QWORD PTR [rip+0x1d8b0],rax        # 22750 <obstack_alloc_failed_handler@@Base+0x6b0>
    4ea0:	48 c7 05 ad d8 01 00 	mov    QWORD PTR [rip+0x1d8ad],0xffffffffffffffff        # 22758 <obstack_alloc_failed_handler@@Base+0x6b8>
    4ea7:	ff ff ff ff 
    4eab:	c6 05 0a d4 01 00 00 	mov    BYTE PTR [rip+0x1d40a],0x0        # 222bc <obstack_alloc_failed_handler@@Base+0x21c>
    4eb2:	e8 e9 f8 ff ff       	call   47a0 <isatty@plt>

```

- mettez en évidence quelques lignes qui contiennent l'instruction syscall

```
[axel@TP2-Secu-SE ~]$ objdump -M intel -d -j .text /usr/bin/ls | grep syscall
[axel@TP2-Secu-SE ~]
```

Effectivement il y en a pas :)

🌞 **Utiliser objdump sur la librairie Glibc**

- vous avez repéré son chemin exact au point d'avant avec ldd

```/lib64/libc.so.6```

- mettez en évidence quelques lignes qui contiennent l'instruction syscall

```
[axel@TP2-Secu-SE ~]$ objdump -M intel -d -j .text /lib64/libc.so.6 | grep -B 5 syscall | head -n 50
   295e8:	75 0e                	jne    295f8 <__libc_start_call_main+0xa8>
   295ea:	ba 3c 00 00 00       	mov    edx,0x3c
   295ef:	90                   	nop
   295f0:	31 ff                	xor    edi,edi
   295f2:	89 d0                	mov    eax,edx
   295f4:	0f 05                	syscall 
--
   3e728:	00 00 00 00 
   3e72c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]

000000000003e730 <__restore_rt>:
   3e730:	48 c7 c0 0f 00 00 00 	mov    rax,0xf
   3e737:	0f 05                	syscall 
--
   3e7e9:	0f 11 74 24 78       	movups XMMWORD PTR [rsp+0x78],xmm6
   3e7ee:	0f 11 bc 24 88 00 00 	movups XMMWORD PTR [rsp+0x88],xmm7
   3e7f5:	00 
   3e7f6:	41 ba 08 00 00 00    	mov    r10d,0x8
   3e7fc:	b8 0d 00 00 00       	mov    eax,0xd
   3e801:	0f 05                	syscall 
--
   3e95b:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

000000000003e960 <kill>:
   3e960:	f3 0f 1e fa          	endbr64 
   3e964:	b8 3e 00 00 00       	mov    eax,0x3e
   3e969:	0f 05                	syscall 
--

000000000003e990 <sigpending>:
   3e990:	f3 0f 1e fa          	endbr64 
   3e994:	be 08 00 00 00       	mov    esi,0x8
   3e999:	b8 7f 00 00 00       	mov    eax,0x7f
   3e99e:	0f 05                	syscall 
--
   3e9db:	00 
   3e9dc:	85 c0                	test   eax,eax
   3e9de:	75 18                	jne    3e9f8 <__sigsuspend+0x28>
   3e9e0:	be 08 00 00 00       	mov    esi,0x8
   3e9e5:	b8 82 00 00 00       	mov    eax,0x82
   3e9ea:	0f 05                	syscall 
--
   3ea01:	e8 5a 77 04 00       	call   86160 <__GI___pthread_enable_asynccancel>
   3ea06:	48 8b 7c 24 08       	mov    rdi,QWORD PTR [rsp+0x8]
   3ea0b:	be 08 00 00 00       	mov    esi,0x8
   3ea10:	41 89 c0             	mov    r8d,eax
   3ea13:	b8 82 00 00 00       	mov    eax,0x82
   3ea18:	0f 05                	syscall 
--
   3ef3a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
```

- trouvez l'instrution syscall qui exécute le syscall close()

```
[axel@TP2-Secu-SE ~]$ objdump -M intel -d -j .text /lib64/libc.so.6 | grep -w -B 5 -A 5 eax,0x3 | grep -B 1 -A 1 syscall
...
--
   94624:	b8 03 00 00 00       	mov    eax,0x3
   94629:	0f 05                	syscall 
   9462b:	48 3d 00 f0 ff ff    	cmp    rax,0xfffffffffffff000
--
...
```

## Part II : Observe

### 1. strace

🌞 **Utiliser strace pour tracer l'exécution de la commande ls**

- faites ```ls``` sur un dossier qui contient des trucs*

```
[axel@TP2-Secu-SE ~]$ strace ls
execve("/usr/bin/ls", ["ls"], 0x7fffc92af030 /* 31 vars */) = 0
brk(NULL)                               = 0x56554bc05000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffe63912360) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=13107, ...}) = 0
mmap(NULL, 13107, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378fb7000
close(3)                                = 0
openat(AT_FDCWD, "/lib64/libselinux.so.1", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0pp\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=175760, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fd378fb5000
mmap(NULL, 181896, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fd378f88000
mmap(0x7fd378f8e000, 110592, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x6000) = 0x7fd378f8e000
mmap(0x7fd378fa9000, 32768, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x21000) = 0x7fd378fa9000
mmap(0x7fd378fb1000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7fd378fb1000
mmap(0x7fd378fb3000, 5768, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fd378fb3000
close(3)                                = 0
openat(AT_FDCWD, "/lib64/libcap.so.2", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0P'\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=36304, ...}) = 0
mmap(NULL, 36920, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fd378f7e000
mmap(0x7fd378f80000, 16384, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x7fd378f80000
mmap(0x7fd378f84000, 8192, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x6000) = 0x7fd378f84000
mmap(0x7fd378f86000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x7000) = 0x7fd378f86000
close(3)                                = 0
openat(AT_FDCWD, "/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\220\227\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0z@\242,\232\202\205O=fvr2\2566J"..., 68, 896) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2539832, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2125744, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fd378c00000
mmap(0x7fd378c28000, 1523712, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7fd378c28000
mmap(0x7fd378d9c000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19c000) = 0x7fd378d9c000
mmap(0x7fd378df4000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1f4000) = 0x7fd378df4000
mmap(0x7fd378dfa000, 53168, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fd378dfa000
close(3)                                = 0
openat(AT_FDCWD, "/lib64/libpcre2-8.so.0", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\220$\0\0\0\0\0\0"..., 832) = 832
fstat(3, {st_mode=S_IFREG|0755, st_size=636840, ...}) = 0
mmap(NULL, 635440, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fd378ee2000
mmap(0x7fd378ee4000, 446464, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x7fd378ee4000
mmap(0x7fd378f51000, 176128, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x6f000) = 0x7fd378f51000
mmap(0x7fd378f7c000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x99000) = 0x7fd378f7c000
close(3)                                = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fd378ee0000
arch_prctl(ARCH_SET_FS, 0x7fd378ee0c40) = 0
set_tid_address(0x7fd378ee0f10)         = 4778
set_robust_list(0x7fd378ee0f20, 24)     = 0
rseq(0x7fd378ee15e0, 0x20, 0, 0x53053053) = 0
mprotect(0x7fd378df4000, 16384, PROT_READ) = 0
mprotect(0x7fd378f7c000, 4096, PROT_READ) = 0
mprotect(0x7fd378f86000, 4096, PROT_READ) = 0
mprotect(0x7fd378fb1000, 4096, PROT_READ) = 0
mprotect(0x56554a39a000, 8192, PROT_READ) = 0
mprotect(0x7fd378fef000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7fd378fb7000, 13107)           = 0
prctl(PR_CAPBSET_READ, CAP_MAC_OVERRIDE) = 1
prctl(PR_CAPBSET_READ, 0x30 /* CAP_??? */) = -1 EINVAL (Invalid argument)
prctl(PR_CAPBSET_READ, CAP_CHECKPOINT_RESTORE) = 1
prctl(PR_CAPBSET_READ, 0x2c /* CAP_??? */) = -1 EINVAL (Invalid argument)
prctl(PR_CAPBSET_READ, 0x2a /* CAP_??? */) = -1 EINVAL (Invalid argument)
prctl(PR_CAPBSET_READ, 0x29 /* CAP_??? */) = -1 EINVAL (Invalid argument)
statfs("/sys/fs/selinux", {f_type=SELINUX_MAGIC, f_bsize=4096, f_blocks=0, f_bfree=0, f_bavail=0, f_files=0, f_ffree=0, f_fsid={val=[0, 0]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NOEXEC|ST_RELATIME}) = 0
statfs("/sys/fs/selinux", {f_type=SELINUX_MAGIC, f_bsize=4096, f_blocks=0, f_bfree=0, f_bavail=0, f_files=0, f_ffree=0, f_fsid={val=[0, 0]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NOEXEC|ST_RELATIME}) = 0
getrandom("\x04\x3d\xbb\xaf\x72\x5d\x62\x77", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x56554bc05000
brk(0x56554bc26000)                     = 0x56554bc26000
access("/etc/selinux/config", F_OK)     = 0
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=2998, ...}) = 0
read(3, "# Locale name alias data base.\n#"..., 4096) = 2998
read(3, "", 4096)                       = 0
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=369, ...}) = 0
mmap(NULL, 369, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378fba000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib64/gconv/gconv-modules.cache", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=26988, ...}) = 0
mmap(NULL, 26988, PROT_READ, MAP_SHARED, 3, 0) = 0x7fd378ed9000
close(3)                                = 0
futex(0x7fd378df9a6c, FUTEX_WAKE_PRIVATE, 2147483647) = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_MEASUREMENT", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MEASUREMENT", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=23, ...}) = 0
mmap(NULL, 23, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378fb9000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_TELEPHONE", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_TELEPHONE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=59, ...}) = 0
mmap(NULL, 59, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378fb8000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_ADDRESS", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_ADDRESS", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=167, ...}) = 0
mmap(NULL, 167, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378fb7000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_NAME", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_NAME", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=77, ...}) = 0
mmap(NULL, 77, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378ed8000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_PAPER", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_PAPER", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=34, ...}) = 0
mmap(NULL, 34, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378ed7000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_MESSAGES", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MESSAGES", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFDIR|0755, st_size=29, ...}) = 0
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MESSAGES/SYS_LC_MESSAGES", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=57, ...}) = 0
mmap(NULL, 57, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378ed6000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_MONETARY", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MONETARY", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=286, ...}) = 0
mmap(NULL, 286, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378ed5000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_COLLATE", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_COLLATE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=2586930, ...}) = 0
mmap(NULL, 2586930, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378800000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_TIME", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_TIME", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=3284, ...}) = 0
mmap(NULL, 3284, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378ed4000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_NUMERIC", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_NUMERIC", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=54, ...}) = 0
mmap(NULL, 54, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378ed3000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_CTYPE", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_CTYPE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=346132, ...}) = 0
mmap(NULL, 346132, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fd378e7e000
close(3)                                = 0
ioctl(1, TCGETS, {B38400 opost isig icanon echo ...}) = 0
ioctl(1, TIOCGWINSZ, {ws_row=46, ws_col=190, ws_xpixel=0, ws_ypixel=0}) = 0
openat(AT_FDCWD, ".", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3
fstat(3, {st_mode=S_IFDIR|0700, st_size=133, ...}) = 0
getdents64(3, 0x56554bc0f580 /* 8 entries */, 32768) = 272
getdents64(3, 0x56554bc0f580 /* 0 entries */, 32768) = 0
close(3)                                = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
write(1, "quiz-blind-test-187140.mp3\n", 27quiz-blind-test-187140.mp3
) = 27
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

- mettez en évidence le syscall pour écrire dans le terminal le résultat du ```ls```

```
write(1, "quiz-blind-test-187140.mp3\n", 27quiz-blind-test-187140.mp3) = 27
```

🌞 **Utiliser strace pour tracer l'exécution de la commande cat**

- faites ```cat``` sur un fichier qui contient des trucs

```
[axel@TP2-Secu-SE ~]$ cat test.txt 
Du contenu un peu random
[axel@TP2-Secu-SE ~]$ strace cat test.txt 
execve("/usr/bin/cat", ["cat", "test.txt"], 0x7ffc09fd7818 /* 31 vars */) = 0
brk(NULL)                               = 0x55c037415000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffd961cbc80) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=13107, ...}) = 0
mmap(NULL, 13107, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af29000
close(3)                                = 0
openat(AT_FDCWD, "/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\220\227\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0 \0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0"..., 48, 848) = 48
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0z@\242,\232\202\205O=fvr2\2566J"..., 68, 896) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2539832, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f199af27000
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2125744, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f199ac00000
mmap(0x7f199ac28000, 1523712, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f199ac28000
mmap(0x7f199ad9c000, 360448, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19c000) = 0x7f199ad9c000
mmap(0x7f199adf4000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1f4000) = 0x7f199adf4000
mmap(0x7f199adfa000, 53168, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f199adfa000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f199af24000
arch_prctl(ARCH_SET_FS, 0x7f199af24740) = 0
set_tid_address(0x7f199af24a10)         = 4785
set_robust_list(0x7f199af24a20, 24)     = 0
rseq(0x7f199af250e0, 0x20, 0, 0x53053053) = 0
mprotect(0x7f199adf4000, 16384, PROT_READ) = 0
mprotect(0x55c036b24000, 4096, PROT_READ) = 0
mprotect(0x7f199af61000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f199af29000, 13107)           = 0
getrandom("\x14\xd6\x1a\xbb\x32\x78\x9b\xcf", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55c037415000
brk(0x55c037436000)                     = 0x55c037436000
openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=2998, ...}) = 0
read(3, "# Locale name alias data base.\n#"..., 4096) = 2998
read(3, "", 4096)                       = 0
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_IDENTIFICATION", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=369, ...}) = 0
mmap(NULL, 369, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af2c000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib64/gconv/gconv-modules.cache", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=26988, ...}) = 0
mmap(NULL, 26988, PROT_READ, MAP_SHARED, 3, 0) = 0x7f199af1d000
close(3)                                = 0
futex(0x7f199adf9a6c, FUTEX_WAKE_PRIVATE, 2147483647) = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_MEASUREMENT", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MEASUREMENT", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=23, ...}) = 0
mmap(NULL, 23, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af2b000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_TELEPHONE", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_TELEPHONE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=59, ...}) = 0
mmap(NULL, 59, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af2a000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_ADDRESS", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_ADDRESS", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=167, ...}) = 0
mmap(NULL, 167, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af29000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_NAME", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_NAME", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=77, ...}) = 0
mmap(NULL, 77, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af1c000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_PAPER", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_PAPER", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=34, ...}) = 0
mmap(NULL, 34, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af1b000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_MESSAGES", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MESSAGES", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFDIR|0755, st_size=29, ...}) = 0
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MESSAGES/SYS_LC_MESSAGES", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=57, ...}) = 0
mmap(NULL, 57, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af1a000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_MONETARY", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_MONETARY", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=286, ...}) = 0
mmap(NULL, 286, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af19000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_COLLATE", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_COLLATE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=2586930, ...}) = 0
mmap(NULL, 2586930, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199a800000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_TIME", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_TIME", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=3284, ...}) = 0
mmap(NULL, 3284, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af18000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_NUMERIC", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_NUMERIC", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=54, ...}) = 0
mmap(NULL, 54, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199af17000
close(3)                                = 0
openat(AT_FDCWD, "/usr/lib/locale/en_US.UTF-8/LC_CTYPE", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/lib/locale/en_US.utf8/LC_CTYPE", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=346132, ...}) = 0
mmap(NULL, 346132, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f199aec2000
close(3)                                = 0
fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}) = 0
openat(AT_FDCWD, "test.txt", O_RDONLY)  = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=25, ...}) = 0
fadvise64(3, 0, 0, POSIX_FADV_SEQUENTIAL) = 0
mmap(NULL, 139264, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f199aea0000
read(3, "Du contenu un peu random\n", 131072) = 25
write(1, "Du contenu un peu random\n", 25Du contenu un peu random
) = 25
read(3, "", 131072)                     = 0
munmap(0x7f199aea0000, 139264)          = 0
close(3)                                = 0
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

- mettez en évidence le syscall qui demande l'ouverture du fichier en lecture

```
openat(AT_FDCWD, "test.txt", O_RDONLY)  = 3
```

- mettez en évidence le syscall qui écrit le contenu du fichier dans le terminal

```
write(1, "Du contenu un peu random\n", 25Du contenu un peu random) = 25
```

🌞 **Utiliser ```strace``` pour tracer l'exécution de curl example.org**

- vous devez utiliser une option de ```strace```
- elle affiche juste un tableau qui liste tous les syscalls  appelés par la commande tracée, et combien de fois ils ont été appelé

```
[axel@TP2-Secu-SE ~]$ strace -c curl exemple.org*
curl: (6) Could not resolve host: exemple.org*
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 25.35    0.000563           3       141           mmap
 21.84    0.000485          18        26           rt_sigaction
 16.88    0.000375         375         1           execve
 11.53    0.000256           4        60        14 openat
  7.47    0.000166           4        35           mprotect
  3.56    0.000079           1        53           close
  3.15    0.000070           1        45           fstat
  2.70    0.000060           1        36           read
  2.16    0.000048           1        47           write
  1.08    0.000024          24         1           clone3
  0.77    0.000017           0        21           futex
  0.54    0.000012           6         2           socketpair
  0.50    0.000011          11         1           socket
  0.45    0.000010           2         5           brk
  0.36    0.000008           4         2           poll
  0.32    0.000007           3         2           newfstatat
  0.27    0.000006           3         2         1 access
  0.23    0.000005           1         3           rt_sigprocmask
  0.18    0.000004           1         4           fcntl
  0.18    0.000004           2         2         1 arch_prctl
  0.14    0.000003           1         2           ioctl
  0.14    0.000003           1         2           getdents64
  0.09    0.000002           2         1           sysinfo
  0.05    0.000001           1         1           set_tid_address
  0.05    0.000001           1         1           set_robust_list
  0.05    0.000001           1         1           rseq
  0.00    0.000000           0         1           munmap
  0.00    0.000000           0         4           pread64
  0.00    0.000000           0         1           pipe
  0.00    0.000000           0         2           statfs
  0.00    0.000000           0         1           prlimit64
  0.00    0.000000           0         1           getrandom
------ ----------- ----------- --------- --------- ----------------
100.00    0.002221           4       507        16 total
```

### 2. sysdig

#### A. Intro

#### B. Use it

🌞 **Utiliser ```sysdig``` pour tracer les syscalls  effectués par ```ls```**

- faites ```ls``` sur un dossier qui contient des trucs (pas un dossier vide)
- mettez en évidence le syscall pour écrire dans le terminal le résultat du ```ls```

```
[axel@TP2-Secu-SE ~]$ sudo sysdig proc.name=ls | grep write
1513 15:59:55.668936283 3 ls (3740) < write res=114 data=.[0m.[01;36mquiz-blind-test-187140.mp3.[0m  random.txt  .[01;31msysdig-0.39.0-x8
```

🌞 **Utiliser sysdig pour tracer les ```syscalls``` effectués par ```cat```**

- faites ```cat``` sur un fichier qui contient des trucs
- mettez en évidence le syscall qui demande l'ouverture du fichier en lecture

```
1593 16:22:45.689447082 2 cat (3795) > openat dirfd=-100(AT_FDCWD) name=test.txt(/home/axel/test.txt) flags=1(O_RDONLY) mode=0
```

- mettez en évidence le syscall qui écrit le contenu du fichier dans le terminal

```
1778 16:24:46.634931688 2 cat (3800) < write res=25 data=Du contenu un peu random.
```

🌞 **Utiliser sysdig pour tracer les syscalls  effectués par votre utilisateur**

```
sudo sysdig user.name=axel
```

🌞 **Livrez le fichier ```curl.scap``` dans le dépôt git de rendu**

Capturer :
```
sudo sysdig proc.name=curl -w curl.scap
```

Relire depuis le fichier :
```
sudo sysdig -r curl.scap
```

Et la capture est [ICI](/TP_2/curl.scap)

## Part III : Service Hardening

### 1. Install NGINX

### 2. NGINX Tracing

🌞 **Tracer l'exécution du programme NGINX**

```
sudo sysdig proc.name=nginx -w nginx.scap
```

Capture [ICI](/TP_2/nginx.scap)

```
[axel@TP2-Secu-SE ~]$ sudo sysdig -r nginx.scap | cut -d ' ' -f7 | sort | uniq | tr -s "\n" " "
accept4 access arch_prctl bind brk clone close connect dup2 epoll_create epoll_create1 epoll_ctl epoll_wait eventfd2 execve exit_group fcntl fstat futex getdents64 geteuid getpid getppid getrandom gettid ioctl io_setup listen lseek mkdir mmap mprotect munmap newfstatat openat prctl pread prlimit pwrite read recvfrom recvmsg rseq rt_sigaction rt_sigprocmask rt_sigreturn rt_sigsuspend sendfile sendmsg sendto setgid setgroups set_robust_list setsid setsockopt set_tid_address setuid socket socketpair statfs sysinfo timerfd_create timerfd_settime umask uname unlink wait4 write writev
```

### 3. NGINX Hardening

🌞 **HARDEN**

Et voici le fichier [nginx.service](./nginx.service)

