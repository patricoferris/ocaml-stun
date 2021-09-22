(lang dune 2.9)

(name stun)

(license ISC)
(authors "Patrick Ferris")
(maintainers "pf341@patricoferris.com")

(generate_opam_files true)

(package
 (name stun)
 (synopsis "Pure OCaml STUN Protocol")
 (description "")
 (depends cstruct))

(package
 (name stun-mirage)
 (synopsis "Pure OCaml STUN Protocol for MirageOS Unikernels")
 (description "")
 (depends stun mirage-types))

(package
 (name stun-lwt)
 (synopsis "Pure OCaml STUN Protocol using Lwt")
 (description "")
 (depends stun mirage-types))

(package
 (name stun-lwt-unix)
 (synopsis "Pure OCaml STUN Protocol for Unix machines")
 (description "")
 (depends stun stun-lwt cohttp-lwt-unix))