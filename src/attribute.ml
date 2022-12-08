open Eio

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

let comprehension_required attr = attribute_to_int attr <= 0x7FFF

type t = { typ : attribute; length : Cstruct.uint16; value : Cstruct.t }

let of_cstruct buff =
  let typ = Cstruct.BE.get_uint16 buff 0 |> int_to_attribute |> Option.get in
  let length = Cstruct.BE.get_uint16 buff 2 in
  let value = Cstruct.sub buff 4 length in
  { typ; length; value }

let padding_required len =
  let rem = len mod 4 in
  if rem = 0 then 0 else 4 - rem

let to_cstruct { typ; length; value } =
  let padding = padding_required length in
  let buff = Cstruct.create (4 + length + padding) in
  Cstruct.BE.set_uint16 buff 0 (attribute_to_int typ);
  Cstruct.BE.set_uint16 buff 2 length;
  Cstruct.blit value 0 buff 4 length;
  buff

let pp ppf t =
  Fmt.pf ppf "{ typ = %s; length = %i; value = %a }"
    (attribute_to_string t.typ)
    t.length Cstruct.hexdump_pp t.value

let equal a b =
  a.typ = b.typ && a.length = b.length && Cstruct.equal a.value b.value

module type S = sig
  type t

  val attribute_type : attribute
  val of_cstruct : Cstruct.t -> (t, [ `Msg of string ]) result
  val to_cstruct : t -> Cstruct.t
  val pp : t Fmt.t
  val equal : t -> t -> bool
end

module Mapped_address = struct
  type t = { ip : Cstruct.t; port : int }

  let v ~ip ~port = { port; ip }
  let attribute_type = MAPPED_ADDRESS

  let of_cstruct buff =
    let family = Cstruct.get_uint8 buff 1 in
    let port = Cstruct.BE.get_uint16 buff 2 in
    match family with
    | 0x01 ->
        let ip = Cstruct.sub buff 4 4 in
        Ok { ip; port }
    | 0x02 ->
        let ip = Cstruct.sub buff 4 16 in
        Ok { ip; port }
    | _ -> Error (`Msg "Unknown IP family")

  let to_cstruct { ip; port } =
    match Cstruct.length ip with
    | 4 ->
        let buff = Cstruct.create 4 in
        Cstruct.set_uint8 buff 1 0x01;
        Cstruct.BE.set_uint16 buff 2 port;
        Cstruct.append buff ip
    | 16 ->
        let buff = Cstruct.create 4 in
        Cstruct.set_uint8 buff 1 0x02;
        Cstruct.BE.set_uint16 buff 2 port;
        Cstruct.append buff ip
    | _ -> failwith "Unexpected IP Address length!"

  let pp ppf { ip; port } =
    let ip = Cstruct.to_string ip |> Net.Ipaddr.of_raw in
    Fmt.pf ppf "Mapped Address@.ip: %a@.port: %i@." Net.Ipaddr.pp ip port

  let equal a b = Int.equal a.port b.port && Cstruct.equal a.ip b.ip
  let ip t = t.ip
  let port t = t.port
end

module Xor_mapped_address = struct
  type t = { ip : Cstruct.t; port : Cstruct.uint16 }

  let v ~ip ~port = { port; ip }
  let ip t = t.ip
  let port t = t.port
  let attribute_type = XOR_MAPPED_ADDRESS

  (* https://datatracker.ietf.org/doc/html/rfc5389#section-15.2 -- host byte order ? ? ? ? *)
  let decode ~txid:_ t =
    let port =
      t.port lxor Int32.(to_int @@ shift_right Packet.magic_cookie 16)
    in
    match Cstruct.length t.ip with
    | 4 ->
        let ip =
          Int32.(logxor (Cstruct.BE.get_uint32 t.ip 0) Packet.magic_cookie)
        in
        let buf = Cstruct.create 4 in
        Cstruct.BE.set_uint32 buf 0 ip;
        { ip = buf; port }
    | _ -> t (* TODO !!!! *)

  let encode ~txid t = decode ~txid t

  let of_cstruct buff =
    let family = Cstruct.get_uint8 buff 1 in
    let port = Cstruct.BE.get_uint16 buff 2 in
    match family with
    | 0x01 ->
        let ip = Cstruct.sub buff 4 4 in
        Ok { ip; port }
    | 0x02 ->
        let ip = Cstruct.sub buff 4 16 in
        Ok { ip; port }
    | _ -> Error (`Msg "Unknown IP family")

  let to_cstruct { ip; port } =
    match Cstruct.length ip with
    | 4 ->
        let buff = Cstruct.create 4 in
        Cstruct.set_uint8 buff 1 0x01;
        Cstruct.BE.set_uint16 buff 2 port;
        Cstruct.append buff ip
    | 16 ->
        let buff = Cstruct.create 8 in
        Cstruct.set_uint8 buff 1 0x01;
        Cstruct.BE.set_uint16 buff 2 port;
        Cstruct.append buff ip
    | _ -> invalid_arg "Ip Address size"

  let pp ppf { ip; port } =
    let ip = Cstruct.to_string ip |> Net.Ipaddr.of_raw in
    Fmt.pf ppf "XOR Mapped Address@.ip: %a@.port: %i@." Net.Ipaddr.pp ip port

  let equal a b = Int.equal a.port b.port && Cstruct.equal a.ip b.ip
end

module Message_integrity = struct
  type t = Digestif.SHA1.t

  let of_long_credentials ~username ~realm ~password (buff : Cstruct.t) =
    let key =
      Digestif.MD5.digest_string (username ^ ":" ^ realm ^ ":" ^ password)
      |> Digestif.MD5.to_raw_string
    in
    Digestif.SHA1.hmac_bigstring ~key buff.buffer

  let of_short_credentials ~password (buff : Cstruct.t) =
    let key =
      Digestif.MD5.digest_string password |> Digestif.MD5.to_raw_string
    in
    Digestif.SHA1.hmac_bigstring ~key buff.buffer
end

module Fingerprint = struct
  (* Fingerprints are used to distinguish STUN packets
     from other packets when multiplexed (e.g. RTP) *)
  type t = Optint.t

  let magic = Optint.of_int32 0x5354554el

  let of_cstruct (buff : Cstruct.t) =
    let t =
      Checkseum.Crc32.(digest_bigstring buff.buffer buff.off buff.len default)
    in
    Optint.logxor t magic
end

module Error_code = struct
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

  let attribute_type = ERROR_CODE

  let of_cstruct buff =
    let class_ = Cstruct.get_uint8 buff 2 in
    let number = Cstruct.get_uint8 buff 3 in
    let reason =
      Cstruct.sub buff 4 (Cstruct.length buff - 4) |> Cstruct.to_string
    in
    Ok { code = (class_ * 100) + number; reason }

  let to_cstruct { code; reason } =
    let buff = Cstruct.create 4 in
    let class_ = code / 100 in
    let number = code mod 100 in
    Cstruct.set_uint8 buff 2 class_;
    Cstruct.set_uint8 buff 3 number;
    Cstruct.append buff (Cstruct.of_string reason)

  let pp ppf { code; reason } = Fmt.pf ppf "error(%i): %s" code reason
  let equal a b = a = b
end
