(* ISC License
 * Copyright (c) 2014-2018 The ocaml-conduit contributors
 * 
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *)

(* Copied and modified from conduit... probably doing something wrong... *)

open Lwt.Infix

module Sockaddr_io = struct
  let shutdown_no_exn fd mode =
    try Lwt_unix.shutdown fd mode
    with Unix.Unix_error (Unix.ENOTCONN, _, _) -> ()

  let make_fd_state () = ref `Open

  let make fd =
    let fd_state = make_fd_state () in
    let close_in () =
      match !fd_state with
      | `Open ->
          fd_state := `In_closed;
          shutdown_no_exn fd Unix.SHUTDOWN_RECEIVE;
          Lwt.return_unit
      | `Out_closed ->
          fd_state := `Closed;
          Lwt_unix.close fd
      | `In_closed (* repeating on a closed channel is a noop in Lwt_io *)
      | `Closed ->
          Lwt.return_unit
    in
    let close_out () =
      match !fd_state with
      | `Open ->
          fd_state := `Out_closed;
          shutdown_no_exn fd Unix.SHUTDOWN_SEND;
          Lwt.return_unit
      | `In_closed ->
          fd_state := `Closed;
          Lwt_unix.close fd
      | `Out_closed (* repeating on a closed channel is a noop in Lwt_io *)
      | `Closed ->
          Lwt.return_unit
    in
    let ic = Lwt_io.of_fd ~close:close_in ~mode:Lwt_io.input fd in
    let oc = Lwt_io.of_fd ~close:close_out ~mode:Lwt_io.output fd in
    (ic, oc)
end

let connect (mode : Conduit_lwt_unix.client) =
  match mode with
  | `TCP (`IP ip, `Port port) ->
      let with_dgram _sockaddr f =
        let fd = Lwt_unix.socket PF_INET Unix.SOCK_DGRAM 17 in
        Lwt.catch
          (fun () -> f fd)
          (fun e ->
            Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)
            >>= fun () -> Lwt.fail e)
      in
      let connect ?src sa =
        with_dgram sa (fun fd ->
            (match src with
            | None -> Lwt.return_unit
            | Some src_sa -> Lwt_unix.bind fd src_sa)
            >>= fun () ->
            Lwt_unix.connect fd sa >>= fun () ->
            let ic, oc = Sockaddr_io.make fd in
            Lwt.return (fd, ic, oc))
      in
      let sa = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ip, port) in
      connect sa >>= fun (_, ic, oc) -> Lwt.return (ic, oc)
  | _ -> failwith ""
