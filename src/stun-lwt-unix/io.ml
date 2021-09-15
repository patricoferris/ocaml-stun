include Cohttp_lwt_unix.IO

let write_cs oc (cs : Cstruct.t) =
  Lwt_io.write_from_bigstring oc cs.buffer cs.off cs.len >>= fun _ ->
  Lwt_io.flush oc

let read_cs oc (cs : Cstruct.t) =
  Lwt_io.read_into_bigstring oc cs.buffer cs.off cs.len >>= fun _ ->
  Lwt.return ()
