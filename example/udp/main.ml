open Stun

let src = Logs.Src.create "stun.client.example" ~doc:"Stun Client"
module Log = (val Logs.src_log src : Logs.LOG)

let info s = Log.info (fun f -> f "%s" s)

let () =
  Fmt_tty.setup_std_outputs ();
  Logs.set_level ~all:true (Some Logs.Debug);
  Logs.set_reporter (Logs_fmt.reporter ())

let packet secure_random = Packet.(create ~secure_random ~typ:Message.(Binding Request) ~payload:Cstruct.empty ())

let main ~sw net random =
  info "Starting stun connection...";
  let client =
    Client.create ~uri:(Uri.of_string "stun.l.google.com") 19302
  in
  let conn = Client.init ~sw net client in
  info "Connection established...";
  let buff = Cstruct.create 40 in
  Client.write_packet conn (packet random);
  match Client.read_packet conn buff with
    | Ok p ->
      let attr = Attribute.of_cstruct p.payload in
      let xor =
        Attribute.Xor_mapped_address.of_cstruct attr.value |> Result.get_ok
      in
      let ip = Attribute.Xor_mapped_address.decode ~txid:p.txid xor in
      Log.info (fun f -> f "Your IP: %a" Attribute.Xor_mapped_address.pp ip)
    | Error (`Msg m) -> failwith m

let () = 
  Eio_main.run @@ fun env ->
  Eio.Std.Switch.run @@ fun sw ->
  (main ~sw (Eio.Stdenv.net env) (Eio.Stdenv.secure_random env))
