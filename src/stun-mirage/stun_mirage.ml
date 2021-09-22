open Stun

let src = Logs.Src.create "stun-mirage" ~doc:"Stun client"

module Log = (val Logs.src_log src : Logs.LOG)

module Client (Stack : Mirage_stack.V4V6) (Random : Mirage_random.S) = struct
  module Packet = Packet.Make (Random)

  type t = {
    address : Ipaddr.t;
    src_port : int;
    dst_port : int;
    handler : (Stun.Packet.t, [ `Msg of string ]) result -> unit Lwt.t;
    stack : Stack.t;
  }

  let create ?(src_port = Stun.default_port) ~address ~dst_port ~handler stack =
    { address; src_port; dst_port; handler; stack }

  let callback ~src:_ ~dst:_ ~src_port:_ t buff =
    let packet = Packet.of_cstruct buff in
    t.handler packet

  let write { dst_port; src_port; address; stack; _ } packet =
    let buff = Packet.to_cstruct packet in
    Stack.UDP.write ~src_port ~dst:address ~dst_port (Stack.udp stack) buff

  let listen t = Stack.listen_udp t.stack ~port:t.src_port (callback t)
end
