#
#  modern cryptography (Monocypher 4.0.2) implemented in C
#
Mono: module
{
	PATH:	con	"$Mono";

	# XChaCha20-Poly1305.  nonce is 24 bytes, key 32.  Returns
	# (ciphertext, tag) where tag is 16 bytes.
	aeadlock:	fn(key: array of byte, nonce: array of byte,
			   ad: array of byte, plain: array of byte):
			   (array of byte, array of byte);

	# Returns the plaintext, or nil if the tag does not verify.
	aeadunlock:	fn(key: array of byte, nonce: array of byte,
			   tag: array of byte, ad: array of byte,
			   cipher: array of byte): array of byte;

	# BLAKE2b.  key may be nil, n is the digest size (1..64).
	blake2b:	fn(msg: array of byte, key: array of byte, n: int):
			   array of byte;

	# X25519 scalar multiplication; both keys are 32 bytes.
	x25519:		fn(sk: array of byte, pk: array of byte): array of byte;
	xpublic:	fn(sk: array of byte): array of byte;

	# EdDSA (BLAKE2b variant).  The secret key is 64 bytes, a seed
	# is 32 and the signature 64.
	edkeypair:	fn(seed: array of byte): (array of byte, array of byte);
	edsign:		fn(sk: array of byte, msg: array of byte): array of byte;
	edcheck:	fn(sig: array of byte, pk: array of byte, msg: array of byte):
			   int;

	# Argon2id, one lane, 32-byte result.  nb_blocks is the work area
	# in 1 KiB blocks (>= 8); nb_passes is the time cost (>= 1).
	argon2:		fn(pass: array of byte, salt: array of byte,
			   nb_blocks, nb_passes: int): array of byte;

	# Zero a buffer.  Dis arrays are not cleared when they are freed,
	# so secrets have to be wiped explicitly.
	wipe:		fn(a: array of byte): int;

	# Constant-time equality, for comparing tags and keys.
	equal:		fn(a: array of byte, b: array of byte): int;

	# Monocypher version, for the record.
	version:	fn(): string;
};
