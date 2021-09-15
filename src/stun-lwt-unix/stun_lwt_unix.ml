let () = Random.self_init ()

module Random = struct
  type g = unit

  let generate ?g:_ len =
    let buff = Cstruct.create len in
    Cstruct.map (fun _ -> Random.int 256 |> char_of_int) buff
end

module Client = Stun_lwt.Client (Random) (Io) (Net)
