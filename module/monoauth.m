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

	# A multiplexed, authenticated connection.
	Link: adt
	{
		name:		string;
		net:		ref Sys->FD;
		send:		chan of (int, int, array of byte);
		news:		chan of (int, ref Sys->FD);
		sessions:	list of ref Sess;
	};
	Sess: adt
	{
		tag:	int;
		fd:	ref Sys->FD;
	};

	link:		fn(keyfile: string, fd: ref Sys->FD, isserver: int): (ref Link, string);
	linkaccept:	fn(l: ref Link): (int, ref Sys->FD);
	linkopen:	fn(l: ref Link, tag: int): ref Sys->FD;
};
