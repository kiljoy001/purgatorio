#
#  mono authentication: EdDSA certificates, X25519 key exchange and an
#  XChaCha20-Poly1305 stream, all from $Mono.
#
Monoauth: module
{
	PATH:	con "/dis/lib/monoauth.dis";

	# Server and client both return an fd for the plaintext side of an
	# encrypted connection, plus the name in the peer's certificate.
	server:	fn(keyfile: string, fd: ref Sys->FD): (ref Sys->FD, string);
	client:	fn(keyfile: string, fd: ref Sys->FD): (ref Sys->FD, string);
};
