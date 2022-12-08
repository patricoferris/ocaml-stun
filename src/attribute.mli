[%%cenum
type attribute =
  (* Comprehension Required *)
  | MAPPED_ADDRESS [@id 0x0001] (* RFC5389 *)
  | USERNAME [@id 0x0006] (* RFC5389 *)
  | MESSAGE_INTEGRITY [@id 0x0008] (* RFC5389 *)
  | ERROR_CODE [@id 0x0009] (* RFC5389 *)
  | UNKNOWN_ATTRIBUTES [@id 0x000A] (* RFC5389 *)
  | CHANNEL_NUMBER [@id 0x000C] (* RFC5766 *)
  | LIFETIME [@id 0x000D] (* RFC5766 *)
  | XOR_PEER_ADDRESS [@id 0x0012] (* RFC5766 *)
  | DATA [@id 0x0013] (* RFC5766 *)
  | REALM [@id 0x0014] (* RFC5389 *)
  | NONCE [@id 0x0015] (* RFC5389 *)
  | XOR_RELAYED_ADDRESS [@id 0x0016] (* RFC5766 *)
  | EVEN_PORT [@id 0x0018] (* RFC5766 *)
  | REQUESTED_TRANSPORT [@id 0x0019] (* RFC5766 *)
  | DONT_FRAGMENT [@id 0x001A] (* RFC5766 *)
  | XOR_MAPPED_ADDRESS [@id 0x0020] (* RFC5389 *)
  | RESERVATION_TOKEN [@id 0x0022] (* RFC5766 *)
  | PRIORITY [@id 0x0024] (* RFC5245 *)
  | USE_CANDIDATE [@id 0x0025] (* RFC5245 *)
  (* Comprehension Option *)
  | SOFTWARE [@id 0x8022] (* RFC5389 *)
  | ALTERNATE_SERVER [@id 0x8023] (* RFC5389 *)
  | FINGERPRINT [@id 0x8028] (* RFC5389 *)
  | ICE_CONTROLLED [@id 0x8029] (* RFC5245 *)
  | ICE_CONTROLLING [@id 0x802A] (* RFC5245 *)
[@@uint16_t]]

type t = { typ : attribute; length : int; value : Cstruct.t }

val comprehension_required : attribute -> bool
(** agents can safely ignore comprehension-optional attributes they
      don't understand, but cannot successfully process a message if it
      contains comprehension-required attributes that are not
      understood.*)

val of_cstruct : Cstruct.t -> t
val to_cstruct : t -> Cstruct.t
val pp : t Fmt.t
val equal : t -> t -> bool

module type S = sig
  type t

  val attribute_type : attribute
  val of_cstruct : Cstruct.t -> (t, [ `Msg of string ]) result
  val to_cstruct : t -> Cstruct.t
  val pp : t Fmt.t
  val equal : t -> t -> bool
end

module Mapped_address : sig
  type t
  (** The mapped address is the reflexive, transport address of the client. *)

  val ip : t -> Cstruct.t
  (** A buffer filled with the IP bytes *)

  val port : t -> int
  (** The port number *)

  val v : ip:Cstruct.t -> port:int -> t

  include S with type t := t
end

module Xor_mapped_address : sig
  type t
  (** Like a {! Mapped_address.t} but encoded with xor, reading from a buffer 
        does not automatically decode the address. *)

  val ip : t -> Cstruct.t
  (** A buffer filled with the IP bytes *)

  val port : t -> int
  (** The port number *)

  val v : ip:Cstruct.t -> port:int -> t

  include S with type t := t

  val decode : txid:Cstruct.t -> t -> t
  val encode : txid:Cstruct.t -> t -> t
end

module Message_integrity : sig
  type t = Digestif.SHA1.t

  val of_long_credentials :
    username:string -> realm:string -> password:string -> Cstruct.t -> t
  (** This function does not apply any [SALSPrep] *)

  val of_short_credentials : password:string -> Cstruct.t -> t
  (** This function does not apply any [SALSPrep] *)
end

module Fingerprint : sig
  type t = Optint.t
  (** The fingerprint for a given {! Cstruct.t}. 
        This is the CRC32 checksum of the data xor-ed with [0x5354554e]. *)

  val of_cstruct : Cstruct.t -> Optint.t
end

module Error_code : sig
  type t = { code : int; reason : string }

  [%%cenum
  type code =
    (* Comprehension Required *)
    | TRY_ALTERNATE [@id 300]
    | BAD_REQUEST [@id 400]
    | UNAUTHORIZED [@id 401]
    | UNKNOWN_ATTRIBUTE [@id 420]
    | STALE_NONCE [@id 438]
    | SERVER_ERROR [@id 500]
  [@@uint16_t]]

  include S with type t := t
end
