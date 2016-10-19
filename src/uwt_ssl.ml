(*  mostly copy&pasted from lwt-ssl,
 *  adapted for uwt. Original copyright information:
 *
 * Lightweight thread library for OCaml
 * http://www.ocsigen.org/lwt
 * Module Lwt_ssl
 * Copyright (C) 2005-2008 Jérôme Vouillon
 * Laboratoire PPS - CNRS Université Paris Diderot
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, with linking exceptions;
 * either version 2.1 of the License, or (at your option) any later
 * version. See COPYING file for details.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *)

open Lwt.Infix

type socket = Uwt.Tcp.t * Unix.file_descr * Ssl.socket

type uninitialized_socket = Uwt.Tcp.t * Unix.file_descr * Ssl.socket

let ssl_socket_of_uninitialized_socket (_,_,socket) = socket

let ssl_socket (_,_,s) = s

exception Retry_read
exception Retry_write

let wrap_call f () =
  try
    f ()
  with
    (Ssl.Connection_error err | Ssl.Accept_error err |
     Ssl.Read_error err | Ssl.Write_error err) as e ->
      match err with
      | Ssl.Error_want_read -> raise Retry_read
      | Ssl.Error_want_write -> raise Retry_write
      | _ -> raise e

let rec repeat_call ?(wait_read=false) ?(wait_write=false) tcp_t f =
  try
    Lwt.return (wrap_call f ())
  with
  | Retry_read ->
    (match wait_read with
    | true -> Uwt.Main.yield ()
    | false ->
      let buf = Bytes.create 0 in
      Uwt.Tcp.read ~buf tcp_t >>= fun _ -> Lwt.return_unit)
    >>= fun () -> repeat_call ~wait_write ~wait_read:true tcp_t f
  | Retry_write ->
    (match wait_write with
    | true -> Uwt.Main.yield ()
    | false ->
      let buf = Bytes.create 0 in
      Uwt.Tcp.write ~buf tcp_t >>= fun _ -> Lwt.return_unit)
    >>= fun () -> repeat_call ~wait_read ~wait_write:true tcp_t f
  | e -> Lwt.fail e

let embed_socket t context =
  let fd = Uwt.Tcp.fileno_exn t in
  (t,fd,Ssl.embed_socket fd context)

let embed_uninitialized_socket t context =
  let fd = Uwt.Tcp.fileno_exn t in
  (t,fd, Ssl.embed_socket fd context)

let ssl_accept t ctx =
  let fd = Uwt.Tcp.fileno_exn t in
  let socket = Ssl.embed_socket fd ctx in
  let res = t,fd,socket in
  repeat_call t (fun () -> Ssl.accept socket) >|= fun () -> res

let ssl_connect t ctx =
  let fd = Uwt.Tcp.fileno_exn t in
  let socket = Ssl.embed_socket fd ctx in
  let res = t,fd,socket in
  repeat_call t (fun () -> Ssl.connect socket) >|= fun () -> res

let ssl_accept_handshake (t, fd, socket) =
  repeat_call t (fun () -> Ssl.accept socket) >>= fun () ->
  Lwt.return (t, fd, socket)

let ssl_perform_handshake (t, fd, socket) =
  repeat_call t (fun () -> Ssl.connect socket) >>= fun () ->
  Lwt.return (t, fd, socket)

let read ?pos ?len (t,_,s) ~buf =
  let pos = match pos with
  | None -> 0
  | Some x -> x
  in
  let dim = Bytes.length buf in
  let len =
    match len with
    | None -> dim - pos
    | Some x -> x
  in
  if pos < 0 || len < 0 || pos > dim - len then
    Lwt.fail (Invalid_argument "Uwt_ssl.read")
  else if len = 0 then
    Lwt.return 0
  else
    repeat_call t
      (fun () ->
         try
           Ssl.read s buf pos len
         with
         | Ssl.Read_error Ssl.Error_zero_return -> 0 )

let read_ba ?pos ?len (t,_,s) ~buf =
  let pos = match pos with
  | None -> 0
  | Some x -> x
  in
  let dim = Uwt_bytes.length buf in
  let len =
    match len with
    | None -> dim - pos
    | Some x -> x
  in
  if pos < 0 || len < 0 || pos > dim - len then
    Lwt.fail (Invalid_argument "Uwt_ssl.read_ba")
  else if len = 0 then
    Lwt.return 0
  else
    repeat_call t
      (fun () ->
         try
           Ssl.read_into_bigarray s buf pos len
         with
         | Ssl.Read_error Ssl.Error_zero_return -> 0)

let write ?pos ?len (t,_,s) ~buf =
  let pos = match pos with
  | None -> 0
  | Some x -> x
  in
  let dim = Bytes.length buf in
  let len =
    match len with
    | None -> dim - pos
    | Some x -> x
  in
  if pos < 0 || len < 0 || pos > dim - len then
    Lwt.fail (Invalid_argument "Uwt_ssl.write")
  else if len = 0 then
    Lwt.return 0
  else
    repeat_call t
      (fun () -> Ssl.write s buf pos len)

let write_string ?pos ?len x ~buf =
  write ?pos ?len x ~buf:(Bytes.unsafe_of_string buf)

let write_ba ?pos ?len (t,_,s) ~buf =
  let pos = match pos with
  | None -> 0
  | Some x -> x
  in
  let dim = Uwt_bytes.length buf in
  let len =
    match len with
    | None -> dim - pos
    | Some x -> x
  in
  if pos < 0 || len < 0 || pos > dim - len then
    Lwt.fail (Invalid_argument "Uwt_ssl.write_ba")
  else if len = 0 then
    Lwt.return 0
  else
    repeat_call t
      (fun () ->  Ssl.write_bigarray s buf pos len)

let ssl_shutdown (t,_,s) =
  repeat_call t (fun () -> Ssl.shutdown s)

let shutdown (t,_,_) =
  Uwt.Tcp.shutdown t

let close_noerr (t,_,_) =
  Uwt.Tcp.close_noerr t

let close_wait (t,_,_) =
  Uwt.Tcp.close_wait t

let close (t,_,_) =
  Uwt.Tcp.close t

let shutdown_and_close ((t,_,_) as w) =
  Lwt.catch ( fun () -> ssl_shutdown w >>= fun () -> Lwt.return_none )
    ( fun exn -> Lwt.return (Some exn) ) >>= fun x ->
  if x <> None ||
     Uwt.Tcp.(is_writable t = false || write_queue_size t <= 0) then (
    Uwt.Tcp.close_noerr t;
    match x with
    | None -> Lwt.return_unit
    | Some x -> Lwt.fail x
  )
  else
    Lwt.finalize ( fun () ->
        Lwt.catch (fun () -> Uwt.Tcp.shutdown t) (function
          | Unix.Unix_error(Unix.ENOTCONN,_,_) -> Lwt.return_unit
          | x -> Lwt.fail x )
      ) ( fun () -> Uwt.Tcp.close_noerr t; Lwt.return_unit )

let out_channel_of_descr ?buffer s =
  Uwt_io.make
    ?buffer
    ~mode:Uwt_io.output
    ~close:(fun () -> shutdown_and_close s)
    (fun buf pos len -> write_ba ~pos ~len s ~buf)

let in_channel_of_descr ?buffer s =
  Uwt_io.make
    ?buffer
    ~mode:Uwt_io.input
    ~close:(fun () -> shutdown_and_close s)
    (fun buf pos len -> read_ba ~len ~pos s ~buf)

let get_tcp_t (t,_,_) = t

let getsockname (t,_,_) =
  Uwt.Tcp.getsockname t

let getpeername (t,_,_) =
  Uwt.Tcp.getpeername t
