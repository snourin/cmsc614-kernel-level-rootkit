cmd_/home/rk/cmsc614-kernel-level-rootkit/part2/rootkit.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000  --build-id  -T ./scripts/module-common.lds -o /home/rk/cmsc614-kernel-level-rootkit/part2/rootkit.ko /home/rk/cmsc614-kernel-level-rootkit/part2/rootkit.o /home/rk/cmsc614-kernel-level-rootkit/part2/rootkit.mod.o;  true
