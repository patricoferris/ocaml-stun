open Lwt.Infix

module Make
    (Stack : Mirage_stack.V4V6)
    (R : Resolver_lwt.S)
    (Random : Mirage_random.S) =
struct
  module S = Stun_mirage.Client (Stack) (Random)
  module Packet = Stun.Packet.Make (Random)

  let wait, resolve = Lwt.wait ()

  let handler p =
    let open Stun in
    let open Rresult in
    let p = match p with Ok v -> v | Error (`Msg m) -> failwith m in
    let attr = Attribute.of_cstruct p.Packet.payload in
    let data =
      Attribute.Xor_mapped_address.of_cstruct attr.Attribute.value
      >>= fun xor ->
      Ok (Attribute.Xor_mapped_address.decode ~txid:p.Packet.txid xor)
    in
    match data with
    | Ok data ->
        Logs.info (fun f ->
            f "Your IP: %a" Attribute.Xor_mapped_address.pp data);
        Lwt.wakeup resolve ()
    | Error (`Msg m) -> Logs.err (fun f -> f "%s" m)

  let start stack resolver _random =
    let uri = Uri.of_string "stun://stun.l.google.com" in
    let port = Key_gen.port () in
    let dst_port = Option.value ~default:Stun.default_port port in
    Logs.info (fun f ->
        f "Connecting to %a on port %i (host is %a)" Uri.pp uri dst_port
          Fmt.(option string)
          (Uri.host uri));
    let s = Resolver.{ name = "stun"; port = Stun.default_port; tls = false } in
    R.set_service
      ~f:(fun t -> if t = "stun" then Lwt.return (Some s) else Lwt.return None)
      resolver;
    R.resolve_uri ~uri resolver >>= fun endpoint ->
    match endpoint with
    | `TLS (_, `TCP (address, _)) | `TCP (address, _) ->
        let stun =
          S.create ~address ~dst_port
            ~handler:(fun p -> Lwt.return @@ handler p)
            stack
        in
        S.listen stun;
        let request =
          Packet.create
            ~typ:Stun.Packet.Message.(Binding Request)
            ~payload:Cstruct.empty ()
        in
        S.write stun request >>= fun _ ->
        wait >>= fun () -> Lwt.return ()
    | t ->
        Lwt.fail_with
          (Fmt.str "Resolution problem: %a" Sexplib.Sexp.pp
             (Conduit.sexp_of_endp t))
end
