open Lwt.Infix
open Stun

module Make (Stack : Mirage_stack.V4V6) (R : Resolver_lwt.S)(Random : Mirage_random.S) = struct 

  module S = Stun_mirage.Client (Stack) (Random)
  module P = Stun.Packet.Make (Random)

  let wait, resolve = Lwt.wait ()

  let handler (p : Packet.t) = 
    let open Stun in 
    let open Packet in
    let open Rresult in
    let attr = Attribute.of_cstruct p.payload in 
    let data = 
      Attribute.Xor_mapped_address.of_cstruct attr.Attribute.value >>= fun xor -> 
      Ok (Attribute.Xor_mapped_address.decode ~txid:p.txid xor)
    in
      match data with 
      Ok data -> (Logs.info (fun f -> f "Information: %a" Attribute.Xor_mapped_address.pp data))
      | Error (`Msg m) -> Logs.err (fun f -> f "%s" m)


  let start stack resolver _random = 
    let uri = Uri.of_string "stun://stun1.l.google.com" in 
    let port = Key_gen.port () in
    let port = Option.value ~default:Stun.default_port port in 
    Logs.info (fun f -> f "Connecting to %a on port %i (host is %a)" Uri.pp uri port Fmt.(option string) (Uri.host uri)); 
    let s = Resolver.{ name = "stun"; port = Stun.default_port; tls = false } in 
    R.set_service ~f:(fun t -> if t = "stun" then Lwt.return (Some s) else Lwt.return None) resolver;
    R.resolve_uri ~uri resolver >>= fun endpoint -> 
    match endpoint with 
      | `TLS (_, (`TCP (address, _))) | `TCP (address, _) -> 
        Logs.info (fun f -> f "IP Address: %a" Ipaddr.pp address);
        let stun = S.create ~address ~port ~handler:(fun p -> Lwt.return @@ handler p) stack in 
        ignore @@ S.input stun;
        let request = P.create ~typ:Stun.Packet.Message.(Binding Request) ~payload:Cstruct.empty () in 
        Logs.info (fun f -> f "%a" Cstruct.hexdump_pp (P.to_cstruct request));
        S.write stun request >>= fun s ->
        (match s with Ok () -> Logs.info (fun f -> f "Wrote request") | Error err -> Logs.info (fun f -> f "ERR: %a" Stack.UDP.pp_error err));
        wait >>= fun () ->
        Lwt.return ()
      | t -> Lwt.fail_with (Fmt.str "Resolution problem: %a" Sexplib.Sexp.pp (Conduit.sexp_of_endp t))
end 