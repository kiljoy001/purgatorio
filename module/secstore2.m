#
# secstore2 -- Monocypher-backed secure store file format
#
# One file is one encrypted blob:
#
#	header || owner || name ||
#		XChaCha20-Poly1305(plaintext) || BLAKE2b-256
#
# The header and owner/name are the AEAD associated data.  The trailing
# digest covers every preceding byte and is a content identifier, not a
# password check.
#
Secstore2: module
{
	PATH:	con "/dis/lib/secstore2.dis";

	VERSION:	con 2;
	KDFARGON2ID:	con 1;
	AEADXCHACHA:	con 1;

	HDRLEN:		con 96;
	SALTLEN:	con 16;
	NONCELEN:	con 24;
	KEYLEN:		con 32;
	TAGLEN:		con 16;
	DIGLEN:		con 32;
	OWNERMAX:	con 64;
	NAMEMAX:	con 255;

	# Argon2id floor and ceiling; m is in 1 KiB blocks.
	MINKIB:		con 65536;
	MAXKIB:		con 262144;
	DEFT:		con 3;
	DEFM:		con 262144;
	DEFP:		con 1;

	MAXPT:		con 8*1024*1024;
	MAXFILE:	con MAXPT+4096;

	Head: adt
	{
		t, m, p, keylen:	int;
		salt:			array of byte;
		nonce:			array of byte;
		ptxlen, epoch, rev:	int;
		ownerlen, namelen:	int;
		owner, name:		string;
	};

	init:		fn();
	headinit:	fn(owner, name: string): ref Head;
	clone:		fn(h: ref Head): ref Head;
	parsehead:	fn(in: array of byte): (int, ref Head, string);
	derive:		fn(h: ref Head, pass: array of byte):
				(array of byte, string);
	sealkey:	fn(h: ref Head, key: array of byte, plain: array of byte):
				(array of byte, string);
	seal:		fn(h: ref Head, pass: array of byte, plain: array of byte):
				(array of byte, string);
	openkey:	fn(in: array of byte, h: ref Head, key: array of byte):
				(array of byte, string);
	open:		fn(in: array of byte, pass: array of byte):
				(array of byte, ref Head, string);
	digest:		fn(in: array of byte): array of byte;
	samekdf:	fn(a, b: ref Head): int;
	validname:	fn(name: string): int;
	hex:		fn(a: array of byte): string;
	unhex:		fn(s: string): array of byte;
	wipe:		fn(a: array of byte);
};
