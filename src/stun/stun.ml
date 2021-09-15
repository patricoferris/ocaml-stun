let default_port = 3478

let default_tls_port = 5349

module Packet = Packet
module Attribute = Attribute

let stun_service = Resolver.{ name = "stun"; port = default_port; tls = false }

let stuns_service =
  Resolver.{ name = "stuns"; port = default_tls_port; tls = true }
