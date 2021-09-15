(*{{{ Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
  }}}*)

(* Borrowed primarily from Cohttp *)

open Lwt.Infix
module IO = Io

let src = Logs.Src.create "stun-lwt-unix.net" ~doc:"Networking for unix stun"

module Log = (val Logs.src_log src : Logs.LOG)

type ctx = { ctx : Conduit_lwt_unix.ctx; resolver : Resolver_lwt.t }
[@@deriving sexp_of]

let default_ctx =
  let resolver = Resolver_lwt_unix.system in
  let () =
    Resolver_lwt.set_service
      ~f:(fun _ -> Lwt.return @@ Some Stun.stun_service)
      resolver
  in
  { resolver; ctx = Conduit_lwt_unix.default_ctx }

let connect_uri ~ctx:{ ctx; resolver } uri =
  Log.debug (fun f -> f "resolving and connecting to %a" Uri.pp uri);
  Resolver_lwt.resolve_uri ~uri resolver >>= fun endp ->
  Log.debug (fun f ->
      f "resolved to %a" Sexplib.Sexp.pp (Conduit.sexp_of_endp endp));
  Conduit_lwt_unix.endp_to_client ~ctx endp >>= fun client ->
  Log.debug (fun f ->
      f "Client: %a" Sexplib.Sexp.pp (Conduit_lwt_unix.sexp_of_client client));
  Conduit_lwt_unix.connect ~ctx client >>= fun (_, ic, oc) ->
  Log.debug (fun f -> f "Connection");
  Lwt.return (ic, oc)

let connect_uri_with_udp ~ctx:{ ctx; resolver } uri =
  Log.debug (fun f -> f "resolving and connecting (with UDP) to %a" Uri.pp uri);
  Resolver_lwt.resolve_uri ~uri resolver >>= fun endp ->
  Log.debug (fun f ->
      f "resolved to %a" Sexplib.Sexp.pp (Conduit.sexp_of_endp endp));
  Conduit_lwt_unix.endp_to_client ~ctx endp >>= fun client ->
  Log.debug (fun f ->
      f "Client: %a" Sexplib.Sexp.pp (Conduit_lwt_unix.sexp_of_client client));
  Conduit_udp.connect client >>= fun conn ->
  Log.debug (fun f -> f "Connection");
  Lwt.return conn

let close c =
  Lwt.catch
    (fun () -> Lwt_io.close c)
    (fun e ->
      Logs.warn (fun f -> f "Closing channel failed: %s" (Printexc.to_string e));
      Lwt.return_unit)

let close_in ic = Lwt.ignore_result (close ic)

let close_out oc = Lwt.ignore_result (close oc)

let close ic oc = Lwt.ignore_result (close ic >>= fun () -> close oc)
