# tcptrace

![Example use (after compile)](example.png)

Run with root permissions (`sudo`) because raw sockets are created.

Not all sites can successfully be traced due to firewall permissions and TCP RSTs.

## How it works

The TCP traceroute mechanism is very similar to normal ping traceroute.

I used socket errors to detect different types of packets.
