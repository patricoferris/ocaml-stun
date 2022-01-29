let default_port = 3478

let default_tls_port = 5349

module Packet = Packet
module Attribute = Attribute

let stun_service = Resolver.{ name = "stun"; port = default_port; tls = false }

let stuns_service =
  Resolver.{ name = "stuns"; port = default_tls_port; tls = true }

module Client = struct
  let src = Logs.Src.create "stun.client" ~doc:"Stun client"
  module Log = (val Logs.src_log src : Logs.LOG)

  type t = { uri : Uri.t; port : int }

  type conn = <Eio.Flow.two_way; Eio.Flow.close>

  let create ~uri port = { uri; port }

  let connect ~sw net sockaddr = 
    Eio.Net.connect ~sw net sockaddr

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
