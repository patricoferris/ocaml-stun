val default_port : int
(** The default UDP port for stun connections *)

val default_tls_port : int
(** The default TLS port for stun(s) connections *)

val stun_service : Resolver.service
(** A resolver service that recognises [stun] as a scheme *)

val stuns_service : Resolver.service
(** Same as {! stun_service} except for TLS stun connections *)

(** {2 Stun Packet}*)

module Packet = Packet


(** {2 Attributes} *)

module Attribute = Attribute

(** {2 STUN Client} *)

module Client : sig
  type t

  type conn = <Eio.Flow.two_way; Eio.Flow.close>

  val create : uri:Uri.t -> int -> t

  val connect : sw:Eio.Std.Switch.t -> Eio.Net.t -> Eio.Net.Sockaddr.t -> conn

  val write_packet : conn -> Packet.t -> unit

  val read_packet : conn -> Cstruct.t -> (Packet.t, [`Msg of string]) result
end
