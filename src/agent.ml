(*

   module Make (R : Mirage_random.S) = struct
     module Packet = Packet.Make(R)

     type handler = Packet.t -> unit

     type t = {
       transactions :
       handler : handler
     }
   end *)
