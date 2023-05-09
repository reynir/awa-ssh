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

open Mirage_crypto_pk

type priv =
  | Rsa_priv of Rsa.priv
  | Ed25519_priv of Mirage_crypto_ec.Ed25519.priv

type pub =
  | Rsa_pub of Rsa.pub
  | Ed25519_pub of Mirage_crypto_ec.Ed25519.pub
  | P256_pub of Mirage_crypto_ec.P256.Dsa.pub
  | P384_pub of Mirage_crypto_ec.P384.Dsa.pub
  | P521_pub of Mirage_crypto_ec.P521.Dsa.pub

let pub_eq a b = match a, b with
  | Rsa_pub rsa, Rsa_pub rsa' ->
    Z.equal rsa.Rsa.e rsa'.Rsa.e && Z.equal rsa.Rsa.n rsa'.Rsa.n
  | Ed25519_pub e, Ed25519_pub e' ->
    Cstruct.equal
      (Mirage_crypto_ec.Ed25519.pub_to_cstruct e)
      (Mirage_crypto_ec.Ed25519.pub_to_cstruct e')
  | P256_pub q, P256_pub q' ->
    Cstruct.equal
      (Mirage_crypto_ec.P256.Dsa.pub_to_cstruct q)
      (Mirage_crypto_ec.P256.Dsa.pub_to_cstruct q')
  | P384_pub q, P384_pub q' ->
    Cstruct.equal
      (Mirage_crypto_ec.P384.Dsa.pub_to_cstruct q)
      (Mirage_crypto_ec.P384.Dsa.pub_to_cstruct q')
  | P521_pub q, P521_pub q' ->
    Cstruct.equal
      (Mirage_crypto_ec.P521.Dsa.pub_to_cstruct q)
      (Mirage_crypto_ec.P521.Dsa.pub_to_cstruct q')
  | _ -> false

let pub_of_priv = function
  | Rsa_priv priv -> Rsa_pub (Rsa.pub_of_priv priv)
  | Ed25519_priv priv -> Ed25519_pub (Mirage_crypto_ec.Ed25519.pub_of_priv priv)

let sshname = function
  | Rsa_pub _ -> "ssh-rsa"
  | Ed25519_pub _ -> "ssh-ed25519"
  | P256_pub _ -> "ecdsa-sha2-nistp256"
  | P384_pub _ -> "ecdsa-sha2-nistp384"
  | P521_pub _ -> "ecdsa-sha2-nistp521"

let comptible_alg p a =
  match p with
  | Rsa_pub _ ->
    begin match a with
      | "ssh-rsa"
      | "rsa-sha2-256"
      | "rsa-sha2-512" -> true
      | _ -> false
    end
  | Ed25519_pub _ ->
    begin match a with
      | "ssh-ed25519" -> true
      | _ -> false
    end
  | P256_pub _ -> String.equal a "ecdsa-sha2-nistp256"
  | P384_pub _ -> String.equal a "ecdsa-sha2-nistp384"
  | P521_pub _ -> String.equal a "ecdsa-sha2-nistp521"

type alg =
  | Rsa_sha1
  | Rsa_sha256
  | Rsa_sha512
  | Ed25519
  | P256
  | P384
  | P521

let hash = function
  | Rsa_sha1 -> `SHA1
  | Rsa_sha256 -> `SHA256
  | Rsa_sha512 -> `SHA512
  | Ed25519 -> `SHA512
  | P256 -> `SHA256
  | P384 -> `SHA384
  | P521 -> `SHA512

let alg_of_string = function
  | "ssh-rsa" -> Ok Rsa_sha1
  | "rsa-sha2-256" -> Ok Rsa_sha256
  | "rsa-sha2-512" -> Ok Rsa_sha512
  | "ssh-ed25519" -> Ok Ed25519
  | "ecdsa-sha2-nistp256" -> Ok P256
  | "ecdsa-sha2-nistp384" -> Ok P384
  | "ecdsa-sha2-nistp521" -> Ok P521
  | s -> Error ("Unknown public key algorithm " ^ s)

let alg_to_string = function
  | Rsa_sha1 -> "ssh-rsa"
  | Rsa_sha256 -> "rsa-sha2-256"
  | Rsa_sha512 -> "rsa-sha2-512"
  | Ed25519 -> "ssh-ed25519"
  | P256 -> "ecdsa-sha2-nistp256"
  | P384 -> "ecdsa-sha2-nistp384"
  | P521 -> "ecdsa-sha2-nistp521"

let preferred_algs = [ Ed25519 ; Rsa_sha256 ; Rsa_sha512 ; Rsa_sha1 ]

let algs_of_typ = function
  | `Ed25519 -> [ Ed25519 ]
  | `Rsa -> [ Rsa_sha256 ; Rsa_sha512 ; Rsa_sha1 ]
  | `P256 -> [ P256 ]
  | `P384 -> [ P384 ]
  | `P521 -> [ P521 ]

let priv_to_typ = function
  | Rsa_priv _ -> `Rsa
  | Ed25519_priv _ -> `Ed25519

let alg_matches typ alg = List.mem alg (algs_of_typ typ)

let signature_equal = Cstruct.equal

let sign alg priv blob =
  match priv with
  | Rsa_priv priv ->
    let hash = hash alg in
    Rsa.PKCS1.sign ~hash ~key:priv (`Message blob)
  | Ed25519_priv priv ->
    Mirage_crypto_ec.Ed25519.sign ~key:priv blob

let verify alg pub ~unsigned ~signed =
  match pub with
  | Rsa_pub key ->
    let hashp h = h = hash alg in
    Rsa.PKCS1.verify ~hashp ~key ~signature:signed (`Message unsigned)
  | Ed25519_pub key ->
    Mirage_crypto_ec.Ed25519.verify ~key signed ~msg:unsigned
  | P256_pub _ | P384_pub _ | P521_pub _ -> false (* TODO *)
