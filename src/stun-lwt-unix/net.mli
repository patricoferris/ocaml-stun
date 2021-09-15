type ctx = { ctx : Conduit_lwt_unix.ctx; resolver : Resolver_lwt.t }
[@@deriving sexp_of]

include Stun_lwt.Net_with_udp with type ctx := ctx and module IO = Io
