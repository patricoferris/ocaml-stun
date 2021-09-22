ocaml-stun
----------

Pure OCaml implementation of the [Session Traversal Utilities for NAT (STUN)](stun) protocol (STUN).

## What is STUN?

Before understanding STUN (and why it exists), you first need to know about Network Address Translation (NAT). NAT allows modifying network address information (primarily in the IP header) whilst a packet is in transit.

Why would you want to do this? Originally it was more for convenience. Instead of having to update every device on a network if it moved, you would only update the NAT. More modern use cases are for preserving the limited amount of IPv4 addresses.

The most typical example involves having one public address (typically provided by an ISP) for multiple, internal, private addresses. The router's job is to transparently expose these devices with private addresses to the internet using the public address. The router then distinguishes between inbound packets and does the correct public-to-private translation.

STUN is a tool used by other protocols (WebRTC, VoIP etc.) to help work around the NAT problem. When trying to establish peer-to-peer connections you want to know what the *outermost* public IP address and port number are for your device. The so-called **reflexive transport address**. Your device may be *many NATs deep*! [rfc5389](rfc5389) gives an example of 2:

```
                               /-----\
                             // STUN  \\
                            |   Server  |
                             \\       //
                               \-----/




                          +--------------+             Public Internet
          ................|     NAT 2    |.......................
                          +--------------+



                          +--------------+             Private NET 2
          ................|     NAT 1    |.......................
                          +--------------+




                              /-----\
                            //  STUN \\
                           |    Client |
                            \\       //               Private NET 1
                              \-----/


                 Figure 1: One Possible STUN Configuration
```

You can discover your *reflexive transport address* by:

```
opam pin . -yn
dune exec -- ./example/lwt-unix-ip/main.exe
```

### Mirage Example

To run the example Mirage code you can run: 

```
opam pin -y .
cd example/unikernel-ip
mirage configure -t unix
make depends
make build
./main.native --port 19302
```

### Things left to do...

 - Make the APIs nicer, you can run the STUN protocol on top of UDP, TCP and TLS-TCP so that should be provided here
 - Retransmission logic for UDP sessions
 - More testing
 - Lots of things...


[stun]: https://datatracker.ietf.org/doc/html/rfc5389
[rfc5389]: https://datatracker.ietf.org/doc/html/rfc5389