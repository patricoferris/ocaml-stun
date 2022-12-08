open Eio

let default_port = 3478
let default_tls_port = 5349

module Packet = Packet
module Attribute = Attribute

module Client = struct
  let src = Logs.Src.create "stun.client" ~doc:"Stun client"

  module Log = (val Logs.src_log src : Logs.LOG)

  type t = { uri : Uri.t; port : int }

  type conn =
    | Flow of Flow.two_way
    | Datagram of Net.datagram_socket * Net.Sockaddr.datagram

  let create ~uri port = { uri; port }

  let init ~sw net { uri; port } =
    let sockaddr = Eio.Net.getaddrinfo net (Uri.to_string uri) |> List.hd in
    Log.debug (fun f ->
        f "Resolved %a to %a" Uri.pp uri Eio.Net.Sockaddr.pp sockaddr);
    match sockaddr with
    | `Tcp (ip, _) ->
        let conn = Eio.Net.connect ~sw net (`Tcp (ip, port)) in
        Flow (conn :> Eio.Flow.two_way)
    | `Unix _ as sockaddr ->
        let conn = Eio.Net.connect ~sw net sockaddr in
        Flow (conn :> Eio.Flow.two_way)
    | `Udp (ip, _) ->
        Datagram
          ( (Eio.Net.datagram_socket ~sw net `UdpV6 :> Net.datagram_socket),
            `Udp (ip, port) )

  let write_packet dst v =
    let cs = Packet.to_cstruct v in
    Log.debug (fun f -> f "Writing packet: %a" Cstruct.hexdump_pp cs);
    match dst with
    | Flow dst -> Flow.copy (Eio.Flow.cstruct_source [ cs ]) dst
    | Datagram (sock, addr) -> Net.send sock addr cs

  let read_packet src buff =
    Log.debug (fun f -> f "Reading packet");
    match src with
    | Datagram (sock, addr) ->
        let rec loop () =
          let from, r = Net.recv sock buff in
          match from with
          | _ when from = addr -> Packet.of_cstruct (Cstruct.sub buff 0 r)
          | _ ->
              Logs.debug (fun f -> f "Received from different addr");
              loop ()
        in
        loop ()
    | Flow src ->
        let rec loop read =
          try
            let r = Eio.Flow.single_read src buff in
            loop (r + read)
          with End_of_file -> read
        in
        let r = loop 0 in
        Packet.of_cstruct (Cstruct.sub buff 0 r)
end
