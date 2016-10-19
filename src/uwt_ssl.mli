(** uwt-ssl integration *)

type socket
(** Wrapper for SSL sockets. *)

type uninitialized_socket
(** Wrapper for SSL sockets that have not yet performed the SSL
    handshake. *)

val ssl_socket : socket -> Ssl.socket
(** Returns the underlying SSL socket used for this wrapper. *)

val ssl_socket_of_uninitialized_socket : uninitialized_socket -> Ssl.socket
(** Returns the underlying SSL socket used for this wrapper. *)


val ssl_accept : Uwt.Tcp.t -> Ssl.context -> socket Lwt.t
val ssl_connect : Uwt.Tcp.t -> Ssl.context -> socket Lwt.t
val embed_socket : Uwt.Tcp.t -> Ssl.context -> socket

val embed_uninitialized_socket :
  Uwt.Tcp.t -> Ssl.context -> uninitialized_socket

val ssl_perform_handshake : uninitialized_socket -> socket Lwt.t
(** Initiate a SSL/TLS handshake on the specified socket (used by clients). *)

val ssl_accept_handshake  : uninitialized_socket -> socket Lwt.t
(** Await a SSL/TLS handshake on the specified socket (used by servers). *)

val read : ?pos:int -> ?len:int -> socket -> buf:Bytes.t -> int Lwt.t
val read_ba : ?pos:int -> ?len:int -> socket -> buf:Uwt.buf -> int Lwt.t

val write : ?pos:int -> ?len:int -> socket -> buf:bytes -> int Lwt.t
val write_string : ?pos:int -> ?len:int -> socket -> buf:string -> int Lwt.t
val write_ba : ?pos:int -> ?len:int -> socket ->  buf:Uwt_bytes.t -> int Lwt.t

val shutdown : socket -> unit Lwt.t
val close_noerr : socket -> unit
val close_wait : socket -> unit Lwt.t
val close : socket -> Uwt.Int_result.unit

val in_channel_of_descr : ?buffer:Uwt_bytes.t -> socket -> Uwt_io.input_channel
val out_channel_of_descr :
  ?buffer:Uwt_bytes.t -> socket -> Uwt_io.output_channel

val ssl_shutdown : socket -> unit Lwt.t
val get_tcp_t : socket -> Uwt.Tcp.t
val getsockname : socket -> Unix.sockaddr Uwt.uv_result
val getpeername : socket -> Unix.sockaddr Uwt.uv_result
