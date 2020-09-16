# Latency for TLS Bechmark

### Introducing latencies on local host
[Blog][]
[More][]

To simulate a far away server, add RTT time to the
localhost device. For example if we add 100 milliseconds
(which then makes 200ms ping time to localhost):

`tc qdisc add dev lo root handle 1:0 netem delay 100msec`

`tc qdisc` trafic control & modify the scheduler (aka
 queuing discipline)
 
`dev lo` device localhost

`root` modify the outbound traffic scheduler (parent to
 all handles)
 
`handle 1:0` handle is 1: (qdisc child of root), followup
 number is the class-id

`netem` use the network emulator to emulate a WAN property

---

To restore the defaults:

`tc qdisc del dev lo root`

---
### Latency of Standards
[Paper Source][]
[sas][]

### my setup

`tc qdisc add dev lo root netem delay 10ms 1.0ms
 distribution normal`

[More]: https://netbeez.net/blog/how-to-use-the-linux-traffic-control/
[Blog]: https://daniel.haxx.se/blog/2010/12/14/add-latency-to-localhost/
[Paper Source]: https://arxiv.org/pdf/1909.08096.pdf
[sas]: https://www.sas.co.uk/blog/what-is-network-latency-how-do-you-use-a-latency-calculator-to-calculate-throughput