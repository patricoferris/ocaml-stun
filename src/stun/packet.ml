(* 
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |0 0|     STUN Message Type     |         Message Length        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         Magic Cookie                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  |                     Transaction ID (96 bits)                  |
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*)

let magic_cookie = 0x2112A442l

module Message = struct
  (* Note: this module assumes 16 bits even if the message is 14 + two zeros *)
  type class_ = Request | Indication | Response | Error

  type t = Binding of class_

  (* Everything in RFC5389 is a binding request i.e. LSB = 1 *)
  let of_cstruct buff =
    match Cstruct.BE.get_uint16 buff 0 with
    | 0x0001 -> Ok (Binding Request)
    | 0x0011 -> Ok (Binding Indication)
    | 0x0101 -> Ok (Binding Response)
    | 0x0111 -> Ok (Binding Error)
    | s -> Error (`Msg ("Unknown message type: " ^ string_of_int s))

  let to_cstruct t =
    let buff = Cstruct.create 2 in
    (match t with
    | Binding Request -> Cstruct.BE.set_uint16 buff 0 0x0001
    | Binding Indication -> Cstruct.BE.set_uint16 buff 0 0x0011
    | Binding Response -> Cstruct.BE.set_uint16 buff 0 0x0101
    | Binding Error -> Cstruct.BE.set_uint16 buff 0 0x0111);
    buff

  let pp ppf = function
    | Binding Request -> Fmt.pf ppf "binding(request)"
    | Binding Indication -> Fmt.pf ppf "binding(indication)"
    | Binding Response -> Fmt.pf ppf "binding(response)"
    | Binding Error -> Fmt.pf ppf "binding(error)"
end

type t = {
  typ : Message.t;
  length : Cstruct.uint16;
  cookie : Cstruct.uint32;
  txid : Cstruct.t;
  payload : Cstruct.t;
}

module Make (R : Mirage_random.S) = struct
  (* The magic cookie field MUST contain the fixed value 0x2112A442 in
     network byte order. *)

  let ( >>= ) a f = Result.map f a

  let txid_length_bits = 96

  let of_cstruct buff =
    let typ = Message.of_cstruct buff in
    let length = Cstruct.BE.get_uint16 buff 2 in
    let cookie = Cstruct.BE.get_uint32 buff 4 in
    let txid = Cstruct.sub buff 8 12 in
    let payload = Cstruct.sub buff 20 length in
    typ >>= fun typ -> { typ; length; cookie; txid; payload }

  let create ?g ~typ ~payload () =
    let txid = R.generate ?g 12 in
    {
      typ;
      length = Cstruct.length payload;
      cookie = magic_cookie;
      txid;
      payload;
    }

  let to_cstruct { typ; length; cookie; txid; payload } =
    assert (cookie = magic_cookie);
    assert (Cstruct.length txid = 12);
    let buff = Cstruct.create 20 in
    let typ = Message.to_cstruct typ in
    Cstruct.blit typ 0 buff 0 2;
    Cstruct.BE.set_uint16 buff 2 length;
    Cstruct.BE.set_uint32 buff 4 cookie;
    Cstruct.blit txid 0 buff 8 12;
    Cstruct.append buff payload

  let pp ppf { typ; length; cookie; txid; payload } =
    Fmt.pf ppf
      "{ type = %a; length = %i; cookie = %ld; txid = %a; payload = %a}"
      Message.pp typ length cookie Cstruct.hexdump_pp txid Cstruct.hexdump_pp
      payload

  let equal a b =
    a.typ = b.typ && a.length = b.length && a.cookie = b.cookie
    && Cstruct.equal a.txid b.txid
    && Cstruct.equal a.payload b.payload
end
