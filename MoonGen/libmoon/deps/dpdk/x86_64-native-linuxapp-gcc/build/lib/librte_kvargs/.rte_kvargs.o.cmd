cmd_rte_kvargs.o = gcc -Wp,-MD,./.rte_kvargs.o.d.tmp  -m64 -pthread  -march=native -DRTE_MACHINE_CPUFLAG_SSE -DRTE_MACHINE_CPUFLAG_SSE2 -DRTE_MACHINE_CPUFLAG_SSE3 -DRTE_MACHINE_CPUFLAG_SSSE3 -DRTE_MACHINE_CPUFLAG_SSE4_1 -DRTE_MACHINE_CPUFLAG_SSE4_2 -DRTE_MACHINE_CPUFLAG_AES -DRTE_MACHINE_CPUFLAG_PCLMULQDQ -DRTE_MACHINE_CPUFLAG_AVX -DRTE_MACHINE_CPUFLAG_RDRAND -DRTE_MACHINE_CPUFLAG_FSGSBASE -DRTE_MACHINE_CPUFLAG_F16C -DRTE_MACHINE_CPUFLAG_AVX2  -I/home/justus/work/porsche/porsche/RTPanalyzer/MoonGen/libmoon/deps/dpdk/x86_64-native-linuxapp-gcc/include -include /home/justus/work/porsche/porsche/RTPanalyzer/MoonGen/libmoon/deps/dpdk/x86_64-native-linuxapp-gcc/include/rte_config.h -W -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition -Wpointer-arith -Wcast-align -Wnested-externs -Wcast-qual -Wformat-nonliteral -Wformat-security -Wundef -Wwrite-strings  -Wimplicit-fallthrough=0 -Wno-format-truncation -I/home/justus/work/porsche/porsche/RTPanalyzer/MoonGen/libmoon/deps/dpdk/lib/librte_kvargs -O3   -Wno-error -o rte_kvargs.o -c /home/justus/work/porsche/porsche/RTPanalyzer/MoonGen/libmoon/deps/dpdk/lib/librte_kvargs/rte_kvargs.c 
