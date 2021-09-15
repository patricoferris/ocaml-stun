open Lwt.Infix
open Stun
open Stun.Packet
module Client = Stun_lwt_unix.Client

let src = Logs.Src.create "stun.client.example" ~doc:"Stun Lwt Unix Client"

module Log = (val Logs.src_log src : Logs.LOG)

let () =
  Fmt_tty.setup_std_outputs ();
  Logs.set_level ~all:true (Some Logs.Info);
  Logs.set_reporter (Logs_fmt.reporter ())

let packet =
  Client.P.create ~typ:Message.(Binding Request) ~payload:Cstruct.empty ()

let main () =
  Log.info (fun f -> f "Starting stun connection...");
  let client =
    Client.create ~uri:(Uri.of_string "stun://stun.l.google.com") 19302
  in
  Client.connect client >>= fun conn ->
  Log.info (fun f -> f "Connection established...");
  Client.write_packet packet conn >>= fun () ->
  Client.read_packet conn >>= fun s ->
  let p =
    Cstruct.of_string (String.concat "" s)
    |> Client.P.of_cstruct |> Result.get_ok
  in
  let attr = Attribute.of_cstruct p.payload in
  let xor =
    Attribute.Xor_mapped_address.of_cstruct attr.value |> Result.get_ok
  in
  let ip = Attribute.Xor_mapped_address.decode ~txid:p.txid xor in
  Fmt.pr "Your IP: %a" Attribute.Xor_mapped_address.pp ip;
  Lwt.return ()

let () = Lwt_main.run (main ())
