val default_port : int
(** The default UDP port for stun connections *)

val default_tls_port : int
(** The default TLS port for stun(s) connections *)

(** {2 Stun Packet}*)

module Packet = Packet


(** {2 Attributes} *)

module Attribute = Attribute

(** {2 STUN Client} *)

module Client : sig
  type t

  type conn = <Eio.Flow.two_way>

  val create : uri:Uri.t -> int -> t

  val init : sw:Eio.Std.Switch.t -> Eio.Net.t -> t -> conn

  val write_packet : conn -> Packet.t -> unit

  val read_packet : conn -> Cstruct.t -> (Packet.t, [`Msg of string]) result
end
