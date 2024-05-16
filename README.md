# SnowSignal
SnowSignal is designed to create a mesh network between instances of the program that will listen for UDP broadcasts received on one node of the network and rebroadcast on all other nodes.

## The Problem


## Usage
### General
``` 
usage: snowsignal.py [-h] [-t TARGET_INTERFACE] [-b BROADCAST_PORT] [-m MESH_PORT]
                     [--rebroadcast-mode {packet,payload}] [--other-relays OTHER_RELAYS [OTHER_RELAYS ...]]
                     [-l {debug,info,warning,error,critical}]

options:
  -h, --help            show this help message and exit
  -t TARGET_INTERFACE, --target-interface TARGET_INTERFACE
                        Target network interface
  -b BROADCAST_PORT, --broadcast-port BROADCAST_PORT
                        Port on which to receive and transmit UDP broadcasts
  -m MESH_PORT, --mesh-port MESH_PORT
                        Port on which this instance will communicate with others via UDP unicast
  --rebroadcast-mode {packet,payload}
                        Transfer the whole packet or just the payload on the mesh network
  --other-relays OTHER_RELAYS [OTHER_RELAYS ...]
                        Manually select other relays to transmit received UDP broadcasts to
  -l {debug,info,warning,error,critical}, --log-level {debug,info,warning,error,critical}
                        Logging level
```

### Docker Swarm
If run in a Docker Swarm then the default configuration should work well with PVAccess. 

There is an additional requirement that the environment variable SERVICENAME be set with the Swarm service's name, e.g. 
```
    environment:
      SERVICENAME: '{{.Service.Name}}'
```

This allows each node in the service to automatically located and connect to the other nodes. The mesh will automatically heal as members enter and leave.

## Observations and Lessons Learned
A number of issues arose as I was developing this utility: 
- I originally attempted to be clever around preventing a UDP broadcast storm by using a hashes of the UDP packets broadcast by a node member and then rejecting broadcast messages that were subsequently received by the same node. (More specifically a time-to-live dictionary so that packets weren't banned forever.) This proved overly complex and the current implementation simply filters out UDP broadcasts with sources with the same MAC address as the individual nodes.
- A PVAccess search request includes the IP address and ephemeral port that the unicast UDP reply should use. Experience shows that implementations ignore this in favour of the packet UDP source IP and port. This is why it's ultimately simpler to copy the whole packet and alter it rather than send the payload and construct a new packet around it.

## Origin of Name
A sensible name for this program would be UDP Broadcast Relay, e.g. UBrR. And brr is being cold. Hence with some helps from a name generator the name SnowSignal.