xdp: xdp_lb_kern.o
	bpftool net detach xdpgeneric dev eth0
	rm -f /sys/fs/bpf/xdp_lb
	bpftool prog load xdp_lb_kern.o /sys/fs/bpf/xdp_lb
	bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_lb dev eth0 

xdp_lb_kern.o: xdp_lb_kern.c 
	clang -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    -I../libbpf/src/build/usr/include/ -I../headers/ \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -o ${@:.o=.ll} $<
	llc -march=bpf -filetype=obj -o $@ ${@:.o=.ll}




