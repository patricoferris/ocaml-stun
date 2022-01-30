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
  type t = { ip : Ipaddr.t; port : int }

  let attribute_type = MAPPED_ADDRESS

  let of_cstruct buff =
    let family = Cstruct.get_uint8 buff 1 in
    let port = Cstruct.BE.get_uint16 buff 2 in
    match family with
    | 0x01 ->
        let ip = Cstruct.BE.get_uint32 buff 4 in
        Ok { ip = V4 (Ipaddr.V4.of_int32 ip); port }
    | 0x02 ->
        let ip = Cstruct.BE.(get_uint64 buff 4, get_uint64 buff 12) in
        Ok { ip = V6 (Ipaddr.V6.of_int64 ip); port }
    | _ -> Error (`Msg "Unknown IP family")

  let to_cstruct = function
    | { ip = V4 ip; port } ->
        let buff = Cstruct.create 8 in
        Cstruct.set_uint8 buff 1 0x01;
        Cstruct.BE.set_uint16 buff 2 port;
        Cstruct.BE.set_uint32 buff 4 (Ipaddr.V4.to_int32 ip);
        buff
    | { ip = V6 ip; port } ->
        let buff = Cstruct.create 20 in
        Cstruct.set_uint8 buff 1 0x02;
        Cstruct.BE.set_uint16 buff 2 port;
        let ip1, ip2 = Ipaddr.V6.to_int64 ip in
        Cstruct.BE.set_uint64 buff 4 ip1;
        Cstruct.BE.set_uint64 buff 12 ip2;
        buff

  let pp ppf { ip; port } =
    Fmt.pf ppf "{ ip = %a; port = %i }" Ipaddr.pp ip port

  let equal a b = a = b
end

module Xor_mapped_address = struct
  type t = { ip : Ipaddr.t; port : Cstruct.uint16 }

  let attribute_type = XOR_MAPPED_ADDRESS

  (* https://datatracker.ietf.org/doc/html/rfc5389#section-15.2 -- host byte order ? ? ? ? *)
  let decode ~txid:_ t =
    let port =
      t.port lxor Int32.(to_int @@ shift_right Packet.magic_cookie 16)
    in
    match t.ip with
    | V4 ip ->
        let ip =
          Int32.(logxor (Ipaddr.V4.to_int32 ip) Packet.magic_cookie)
          |> Ipaddr.V4.of_int32
        in
        { ip = V4 ip; port }
    | V6 ip ->
        (* TODO... *)
        (* let xor1, xor2 =
             let buff = Cstruct.create 16 in
             Cstruct.BE.set_uint32 buff 0 Packet.magic_cookie;
             Cstruct.blit txid 0 buff 4 12;
             Cstruct.BE.get_uint64 buff 0, Cstruct.BE.get_uint64 buff 8
           in
           let ip1, ip2 = Ipaddr.V6.to_int64 ip in
           let ip = Ipaddr.V6.of_int64 (Int64.logxor ip1 xor1, Int64.logxor ip2 xor2) in *)
        { ip = V6 ip; port }

  let encode ~txid t = decode ~txid t

  let of_cstruct buff =
    let family = Cstruct.get_uint8 buff 1 in
    let port = Cstruct.BE.get_uint16 buff 2 in
    match family with
    | 0x01 ->
        let ip = Cstruct.BE.get_uint32 buff 4 in
        Ok { ip = V4 (Ipaddr.V4.of_int32 ip); port }
    | 0x02 ->
        let ip = Cstruct.BE.(get_uint64 buff 4, get_uint64 buff 12) in
        Ok { ip = V6 (Ipaddr.V6.of_int64 ip); port }
    | _ -> Error (`Msg "Unknown IP family")

  let to_cstruct = function
    | { ip = V4 ip; port } ->
        let buff = Cstruct.create 8 in
        Cstruct.set_uint8 buff 1 0x01;
        Cstruct.BE.set_uint16 buff 2 port;
        Cstruct.BE.set_uint32 buff 4 (Ipaddr.V4.to_int32 ip);
        buff
    | { ip = V6 ip; port } ->
        let buff = Cstruct.create 20 in
        Cstruct.set_uint8 buff 1 0x01;
        Cstruct.BE.set_uint16 buff 2 port;
        let ip1, ip2 = Ipaddr.V6.to_int64 ip in
        Cstruct.BE.set_uint64 buff 4 ip1;
        Cstruct.BE.set_uint64 buff 12 ip2;
        buff

  let pp ppf { ip; port } =
    Fmt.pf ppf "{ ip = %a; port = %i }" Ipaddr.pp ip port

  let equal a b = a = b
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
