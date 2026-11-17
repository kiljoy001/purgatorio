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

	read:	fn(h: int, buf: array of byte): int;
	write:	fn(h: int, buf: array of byte): int;
	close:	fn(h: int);

	# Mint a self-signed ECDSA P-256 certificate.  The times are
	# UTCTime strings ("YYMMDDhhmmssZ").  Returns (cert, key, error).
	certgen: fn(cn: string, notbefore: string, notafter: string):
		(array of byte, array of byte, string);
};
