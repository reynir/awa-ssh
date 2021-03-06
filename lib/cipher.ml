(*
 * Copyright (c) 2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Sexplib.Conv
open Rresult.R
open Util
open Nocrypto.Cipher_block.AES

type t =
  | Plaintext
  | Aes128_ctr
  | Aes192_ctr
  | Aes256_ctr
  | Aes128_cbc
  | Aes192_cbc
  | Aes256_cbc

type cipher_key =
  | Plaintext_key
  | Aes_ctr_key of CTR.key
  | Aes_cbc_key of CBC.key

type key = t * cipher_key

let to_string = function
  | Plaintext   -> "none"
  | Aes128_ctr -> "aes128-ctr"
  | Aes192_ctr -> "aes192-ctr"
  | Aes256_ctr -> "aes256-ctr"
  | Aes128_cbc -> "aes128-cbc"
  | Aes192_cbc -> "aes192-cbc"
  | Aes256_cbc -> "aes256-cbc"

let of_string = function
  | "none"       -> ok Plaintext
  | "aes128-ctr" -> ok Aes128_ctr
  | "aes192-ctr" -> ok Aes192_ctr
  | "aes256-ctr" -> ok Aes256_ctr
  | "aes128-cbc" -> ok Aes128_cbc
  | "aes192-cbc" -> ok Aes192_cbc
  | "aes256-cbc" -> ok Aes256_cbc
  | s -> error ("Unknown cipher " ^ s)

let key_len = function
  | Plaintext  -> 0
  | Aes128_ctr -> 16
  | Aes192_ctr -> 24
  | Aes256_ctr -> 32
  | Aes128_cbc -> 16
  | Aes192_cbc -> 24
  | Aes256_cbc -> 32

let iv_len = function
  | Plaintext -> 0
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> CBC.block_size

let block_len = function
  | Plaintext -> 8
  | Aes128_ctr | Aes192_ctr | Aes256_ctr -> CTR.block_size
  | Aes128_cbc | Aes192_cbc | Aes256_cbc -> CBC.block_size

let known s = is_ok (of_string s)

let preferred = [ Aes128_ctr; Aes192_ctr; Aes256_ctr;
                  Aes128_cbc; Aes192_cbc; Aes256_cbc; ]
