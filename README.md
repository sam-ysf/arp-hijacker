# Arp Hijacker
This is a basic ARP cache poisoning tool that can be used to execute a man in the middle attack. The tool does not set the attacking machine to act as a packet forwarder, which must be implemented via other means (<https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/load_balancer_administration/s1-lvs-forwarding-vsa>).


Usage
--------------------------------------------------------------------------------
```Bash
hijack
  -i<interface>
  -g<gateway-ip-addr>
  -t<victim-ip-addr>
  -r<retransmit-interval-in-seconds>
```

--------------------------------------------------------------------------------
This software is entirely in the public domain and is provided as is, without restricitions. See the LICENSE for more information.

