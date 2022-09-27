# p4-cuckoo-hash

Cuckoo Hash implementation in P4 for behavioral model. 
In Makefile you find command to monitor the structure behavior.

NOTE: sending packets at high data rate may disrupt its behavior, limit packet rate
e.g. sudo tcpreplay -i <interface> -M 1 // 1Mbps
