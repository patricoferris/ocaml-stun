open Stun

module Client (Stack : Mirage_stack.V4V6) (Random : Mirage_random.S) = struct
  module Packet = Packet.Make (Random)

  type t = {
    address : Ipaddr.t;
    port : int;
    handler : Stun.Packet.t -> unit Lwt.t;
    stack : Stack.t;
  }

  let create ~address ~port ~handler stack = { address; port; handler; stack }

  let callback ~src:_ ~dst:_ ~src_port:_ t buff =
    let packet = Packet.of_cstruct buff in
    match packet with
    | Ok packet -> t.handler packet
    | Error (`Msg m) -> Fmt.failwith "Error parsing incoming packet: %s" m

  let write t packet =
    let buff = Packet.to_cstruct packet in
    Stack.UDP.write ~dst:t.address ~dst_port:t.port (Stack.udp t.stack) buff

  let input t =
    Stack.listen_udp t.stack ~port:t.port (callback t);
    Stack.listen t.stack
end
