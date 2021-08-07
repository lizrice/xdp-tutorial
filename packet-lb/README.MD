# Attaching classifier 

See https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/

sudo tc qdisc add dev docker0 clsact
sudo tc filter add dev docker0 ingress bpf obj xdp_prog_kern.o sec lb

Seems like it needs to be on the egress for us to see it
sudo tc filter add dev docker0 egress bpf obj xdp_prog_kern.o sec lb

XDP 

 sudo ip link set dev docker0 xdpgeneric obj xdp_prog_kern.o sec xdp_packet_parser
 
Looking for this:
 $ sudo bpftool net list
xdp:
docker0(3) generic id 116

tc:
docker0(3) clsact/egress xdp_prog_kern.o:[lb] id 167

flow_dissector:

Deleting:

sudo bpftool net detach xdpgeneric dev docker0
sudo tc filter del dev docker0 egress

See also `make xdp`, `make tc`

# Simple fake web server

while true ; do  echo -e "HTTP/1.1 200 OK\n\n $(date)" | nc -l -p 1500  ; done
Or using yeasy/simple-web

# Reading from bpf_printk trace

```
cd ~/libbpf_beginners
sudo ./hello
```

# Network interfaces

If I want to attach my program to a network interface, I need to be able to see
it e.g. with `ip a`. Docker starts network namespaces anonymously and they don't
show up from the host with, for example, lsns. 

```
sudo touch /run/netns/liz_ns
sudo mount -o bind /proc/132830/ns/net /run/netns/liz_ns
```

Get the proc number from a sleep process inside the container

From https://gist.github.com/cfra/39f4110366fa1ae9b1bddd1b47f586a3

Not sure this is super helpful though, going back to running xdp loader from
inside the container (needs to be privileged)

`ip link set dev eth0 xdpgeneric obj xdp_prog_kern.o sec xdp_packet_parser`

# XDP Tutorial namespaces

eval $(../testenv/testenv.sh alias)