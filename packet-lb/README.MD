# Set up 

```bash
docker run -d --rm --name backend-A -h backend-A --env TERM=xterm-color nginxdemos/hello:plain-text
docker run -d --rm --name backend-B -h backend-B --env TERM=xterm-color nginxdemos/hello:plain-text
docker run --rm -it -h client --name client --env TERM=xterm-color ubuntu
docker run --rm -it -v ~/xdp-tutorial:/xdp --privileged -h lb --name lb --env TERM=xterm-color ubuntu-working
```

Exec into backend-A and install tcpdump with `apk add tcpdump` so we can see incoming
traffic there.

Run something that tails the output from BPF trace 

The ubuntu-working image has dependencies installed: 

```
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential make
```

Change the IP address and that's not sufficient, because you're sending the
packet straight back out the port it came in on. So we need to change the dest
ethernet address. 

As soon as you change the IP address, you have to fix up the checksum

Change dest IP & eth gets it to the backend, but if the backend tried to send it
back to the client the client doesn't know about this connection. So we need to
have the response come back via the LB.

