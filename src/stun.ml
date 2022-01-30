let default_port = 3478

let default_tls_port = 5349

module Packet = Packet
module Attribute = Attribute

module Client = struct
  let src = Logs.Src.create "stun.client" ~doc:"Stun client"
  module Log = (val Logs.src_log src : Logs.LOG)

  type t = { uri : Uri.t; port : int }

  type conn = <Eio.Flow.two_way>

  let create ~uri port = { uri; port }

  let init ~sw net { uri; port } = 
    let sockaddr = Eio.Net.resolve ~sw net uri in
    Log.debug (fun f -> f "Resolved %a to %a" Uri.pp uri Eio.Net.Sockaddr.pp sockaddr);
    match sockaddr with
      | `Tcp (ip, _) ->
        let conn = Eio.Net.connect ~sw net (`Tcp (ip, port)) in
        (conn :> <Eio.Flow.two_way>)
      | `Unix _ as sockaddr -> 
        let conn = Eio.Net.connect ~sw net sockaddr in
        (conn :> <Eio.Flow.two_way>)
      | `Udp (ip, _) -> 
        Eio.Net.init ~sw net (`Udp (ip, port))

  let write_packet dst v =
    let cs = Packet.to_cstruct v in
    Log.debug (fun f ->
        f "Writing packet: %a" Cstruct.hexdump_pp cs);
    Eio.Flow.copy (Eio.Flow.cstruct_source [ cs ]) dst

  let read_packet src buff =
    let r =  Eio.Flow.read_into src buff in
    Log.debug (fun f -> f "Read %i bytes" r);
    Packet.of_cstruct buff
end
