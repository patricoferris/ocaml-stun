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

module Attribute = Attribute
(** {2 Attributes} *)
