open Stun
module P = Packet

let list_to_cstruct xs =
  let open Cstruct in
  let buf = create (List.length xs) in
  List.iteri (set_uint8 buf) xs;
  buf

(* Test from https://github.com/nodertc/stun/blob/master/test/message/decode.js *)
let xor_packet =
  list_to_cstruct
    [
      0;
      0x01;
      (* Type *)
      0x00;
      12;
      (* Length *)
      0x21;
      0x12;
      0xa4;
      0x42;
      (* Cookie *)
      0xd0;
      0x05;
      0x58;
      0x70;
      0x7b;
      0xb8;
      0xcc;
      0x6a;
      0x63;
      0x3a;
      0x9d;
      0xf7;
      (* Transaction *)
      0;
      0x20;
      (* XOR_MAPPED_ADDRESS *)
      0;
      8;
      (* Length *)
      0;
      (* Reserved *)
      0x1;
      (* Family *)
      0xd9;
      0x36;
      (* Port *)
      0xe1;
      0xba;
      0xa5;
      0x61;
      (* Ip *)
    ]

let packet = Alcotest.testable P.pp P.equal
let attribute = Alcotest.testable Attribute.pp Attribute.equal

let xor_mapped_address =
  Alcotest.testable Attribute.Xor_mapped_address.pp
    Attribute.Xor_mapped_address.equal

let cstruct = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal
let err = Alcotest.of_pp (fun ppf (`Msg m) -> Fmt.pf ppf "%s" m)

let test_packet () =
  let decode = P.of_cstruct xor_packet in
  let expect =
    Packet.
      {
        typ = Packet.Message.(Binding Request);
        length = 12;
        cookie = Packet.magic_cookie;
        txid =
          list_to_cstruct
            [
              0xd0;
              0x05;
              0x58;
              0x70;
              0x7b;
              0xb8;
              0xcc;
              0x6a;
              0x63;
              0x3a;
              0x9d;
              0xf7;
            ];
        payload =
          list_to_cstruct
            [ 0; 0x20; 0; 8; 0; 0x1; 0xd9; 0x36; 0xe1; 0xba; 0xa5; 0x61 ];
      }
  in
  Alcotest.(check (result packet err)) "same cstruct" (Ok expect) decode

let test_encode () =
  let expect = xor_packet in
  let packet =
    Packet.
      {
        typ = Packet.Message.(Binding Request);
        length = 12;
        cookie = Packet.magic_cookie;
        txid =
          list_to_cstruct
            [
              0xd0;
              0x05;
              0x58;
              0x70;
              0x7b;
              0xb8;
              0xcc;
              0x6a;
              0x63;
              0x3a;
              0x9d;
              0xf7;
            ];
        payload =
          list_to_cstruct
            [ 0; 0x20; 0; 8; 0; 0x1; 0xd9; 0x36; 0xe1; 0xba; 0xa5; 0x61 ];
      }
  in
  Alcotest.(check cstruct) "same cstruct" expect (P.to_cstruct packet)

let test_attribute () =
  let decode = P.of_cstruct xor_packet in
  let attr =
    Result.map (fun (p : Packet.t) -> Attribute.of_cstruct p.payload) decode
  in
  let expect =
    Attribute.
      {
        typ = XOR_MAPPED_ADDRESS;
        length = 8;
        value = list_to_cstruct [ 0; 0x1; 0xd9; 0x36; 0xe1; 0xba; 0xa5; 0x61 ];
      }
  in
  Alcotest.(check (result attribute err)) "same attribute" (Ok expect) attr

let test_xor_mapped_attr () =
  let open Attribute in
  let packet = P.of_cstruct xor_packet |> Result.get_ok in
  let attribute =
    {
      typ = XOR_MAPPED_ADDRESS;
      length = 8;
      value = list_to_cstruct [ 0; 0x1; 0xd9; 0x36; 0xe1; 0xba; 0xa5; 0x61 ];
    }
  in
  let expect =
    Xor_mapped_address.v ~ip:(Cstruct.of_string "\192\168\001\035") ~port:63524
  in
  let xor = Xor_mapped_address.of_cstruct attribute.value in
  let xor = Result.map (Xor_mapped_address.decode ~txid:packet.txid) xor in
  Alcotest.(check (result xor_mapped_address err))
    "same attribute" (Ok expect) xor

let test_xor_mapped_attr_encode_decode () =
  let open Attribute in
  let packet = P.of_cstruct xor_packet |> Result.get_ok in
  let attribute =
    {
      typ = XOR_MAPPED_ADDRESS;
      length = 8;
      value = list_to_cstruct [ 0; 0x1; 0xd9; 0x36; 0xe1; 0xba; 0xa5; 0x61 ];
    }
  in
  let xor_actual = Xor_mapped_address.of_cstruct attribute.value in
  let xor =
    Result.map (Xor_mapped_address.decode ~txid:packet.txid) xor_actual
  in
  let xor = Result.map (Xor_mapped_address.encode ~txid:packet.txid) xor in
  Alcotest.(check (result xor_mapped_address err))
    "same attribute" xor_actual xor

let test_xor_mapped_ipv6 () =
  let open Attribute in
  let ip =
    (* fe80::dc2b:44ff:fe20:6009 *)
    let first, second = (-108086391056891904L, -31432695L) in
    let buf = Cstruct.create 16 in
    Cstruct.BE.set_uint64 buf 0 first;
    Cstruct.BE.set_uint64 buf 8 second;
    buf
  in
  let xor = Xor_mapped_address.v ~ip ~port:21254 in
  let txid =
    list_to_cstruct
      [ 0x01; 0x02; 0x03; 0x04; 0x01; 0x02; 0x03; 0x04; 0x01; 0x02; 0x03; 0x04 ]
  in
  let encode = Xor_mapped_address.encode ~txid xor in
  let decode = Xor_mapped_address.decode ~txid encode in
  Alcotest.(check xor_mapped_address) "same attribute" xor decode

let test_decode_encode () =
  let decode = P.of_cstruct xor_packet in
  let encode = Result.map P.to_cstruct decode in
  Alcotest.(check (result cstruct err)) "same cstruct" (Ok xor_packet) encode

let tests =
  Alcotest.
    [
      test_case "packet_decode" `Quick test_packet;
      test_case "packet_encode" `Quick test_encode;
      test_case "packet_attribute" `Quick test_attribute;
      test_case "packet_xor_mapped_address" `Quick test_xor_mapped_attr;
      test_case "packet_xor_encoding" `Quick test_xor_mapped_attr_encode_decode;
      test_case "packet_xor_ipv6" `Quick test_xor_mapped_ipv6;
      test_case "packet_encode_decode" `Quick test_decode_encode;
    ]
