let src = Logs.Src.create "stun-lwt.client" ~doc:"Stun client using lwt"

module Log = (val Logs.src_log src : Logs.LOG)

module type Net_with_udp = sig
  include Cohttp_lwt.S.Net

  val connect_uri : ctx:ctx -> Uri.t -> (IO.ic * IO.oc) Lwt.t

  val connect_uri_with_udp : ctx:ctx -> Uri.t -> (IO.ic * IO.oc) Lwt.t
end

module type IO_with_cstruct = sig
  include Cohttp_lwt.S.IO

  val write_cs : oc -> Cstruct.t -> unit Lwt.t

  val read_cs : ic -> Cstruct.t -> unit Lwt.t
end

module Client
    (R : Mirage_random.S)
    (IO : IO_with_cstruct)
    (Net : Net_with_udp with module IO = IO) =
struct
  module P = Stun.Packet.Make (R)

  type t = { uri : Uri.t; port : int }

  let create ~uri port = { uri; port }

  let connect ?(ctx = Net.default_ctx) ?(proto = `Udp) t =
    let uri = Uri.with_port t.uri (Some t.port) in
    if proto = `Udp then Net.connect_uri_with_udp ~ctx uri
    else Net.connect_uri ~ctx uri

  let write_packet v (_, oc) =
    Log.debug (fun f ->
        f "Writing packet: %a" Cstruct.hexdump_pp (P.to_cstruct v));
    let cs = P.to_cstruct v in
    Net.IO.write_cs oc cs

  let read_packet (ic, _) =
    let open Lwt.Infix in
    Log.debug (fun f -> f "Reading packet");
    Net.IO.read ic 1000 >|= fun s -> [ s ]
  (* let rec aux lines =
       (Net.IO.read_line ic) >>= function
       | None -> Lwt.return @@ List.rev lines
       | Some l -> aux (l :: lines)
     in
       aux [] *)
end
