open Mirage

let stack = generic_stackv4v6 default_network

let rand = Mirage.default_random
let resolve = resolver_dns stack
let port =
  let doc = Key.Arg.info ~doc:"Port to connect to." ["port"] in
  Key.(create "port" Arg.(opt (some int) None doc))

let address =
  let doc = Key.Arg.info ~doc:"Address to connect to." ["address"] in
  Key.(create "address" Arg.(required ip_address doc))

let main =
  let packages = [
    package "uri.services"; package "stun-mirage";
  ] in
  let keys = Key.[ v address; v port ] in
  foreign
    ~packages ~keys
    "Unikernel.Make" (stackv4v6 @-> resolver @-> random @-> job)

let () =
  register "stun" [main $ stack $ resolve $ rand]