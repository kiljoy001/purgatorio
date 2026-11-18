#
#  tls: TLS 1.2 as an Inferno builtin module (BearSSL)
#
#  The certificate and key are byte arrays returned by certgen and
#  persisted by the caller; the module never touches the filesystem.
#  Handles are small integers; close frees the connection.
#
TLS: module
{
	PATH:	con "$TLS";

	# Wrap a connected fd with a server-side TLS 1.2 session.
	# cert is a DER certificate; key is the 32-byte ECDSA P-256
	# private scalar.  Returns a handle, or (-1, error).
	accept:	fn(fd: int, cert: array of byte, key: array of byte):
		(int, string);

	# Like accept, but pre holds bytes already read off fd.  The
	# caller can peek at a ClientHello, then hand those bytes back
	# so the session sees an unbroken record stream.
	acceptpre: fn(fd: int, cert: array of byte, key: array of byte,
		pre: array of byte): (int, string);

	read:	fn(h: int, buf: array of byte): int;
	write:	fn(h: int, buf: array of byte): int;
	close:	fn(h: int);

	# Mint a self-signed ECDSA P-256 certificate.  The times are
	# UTCTime strings ("YYMMDDhhmmssZ").  Returns (cert, key, error).
	certgen: fn(cn: string, notbefore: string, notafter: string):
		(array of byte, array of byte, string);

	# AES-128-GCM with a 12-byte nonce; seal returns cipher||tag,
	# open returns plaintext or nil on a bad tag.
	gcmseal: fn(key: array of byte, nonce: array of byte,
		ad: array of byte, plain: array of byte): array of byte;
	gcmopen: fn(key: array of byte, nonce: array of byte,
		ad: array of byte, cipher: array of byte): array of byte;

	# ECDSA P-256 / SHA-256 signature (ASN.1 DER) over msg.
	sign: fn(key: array of byte, msg: array of byte): array of byte;

	# Verify an ASN.1 ECDSA P-256/SHA-256 signature over a 32-byte
	# hash.  pub is the 65-byte uncompressed point (04||X||Y).
	# Returns 1 if the signature is valid.
	ecverify: fn(pub: array of byte, hash: array of byte,
		sig: array of byte): int;
};
