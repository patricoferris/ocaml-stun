let main ~sw env = 
  let uri = Uri.of_string "localhost" in
  let net = Eio.Stdenv.net env in
  Eio.Net.resolve ~sw net uri

let () =
  Eio_main.run @@ fun env ->
  Eio.Std.Switch.run @@ fun sw -> 
  let sockaddr = main ~sw env in
  Eio.Net.Sockaddr.pp Format.std_formatter sockaddr
