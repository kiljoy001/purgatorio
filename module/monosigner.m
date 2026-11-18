#
#  The monoca signer key: one secret file, encrypted at rest when a
#  key-encryption key is available, and a separate public file that
#  every verifier can hold.
#
Monosigner: module
{
	PATH:	con "/dis/lib/monosigner.dis";

	# secret returns the 64-byte EdDSA secret key from path.
	# keyfile names the key-encryption key; when it is empty,
	# /n/host/keydb/mono.key is tried if it exists.  A plaintext
	# signer file is accepted as is.
	secret:	fn(path, keyfile: string): (array of byte, string);

	# pub returns the current signer's public key (the first pk line),
	# falling back to the secret file when path+".pub" is missing.
	pub:	fn(path: string): (array of byte, string);

	# pubs returns every trusted public key.  A rotation appends the
	# new key, so old certificates and epochs keep verifying while the
	# new key is introduced.
	pubs:	fn(path: string): (list of array of byte, string);

	# addpub appends another trusted public key, unless already listed.
	addpub:	fn(path: string, pk: array of byte): string;

	# save writes sk to path, encrypted when a key is available, and
	# publishes the public half in path+".pub".
	save:	fn(path, keyfile: string, sk: array of byte): string;

	# pkof is the public half of a 64-byte EdDSA secret key.
	pkof:	fn(sk: array of byte): array of byte;

	# keypath resolves the key file: explicit, else the default.
	keypath:	fn(explicit: string): string;
};
