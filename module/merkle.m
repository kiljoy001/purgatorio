#
#  merkle: sorted Merkle tree over identity leaves
#
#  Leaves are sorted by their hash, which gives inclusion proofs and,
#  with the two neighbouring leaves, a proof that a key is absent.
#  Hashing is Monocypher's BLAKE2b, so this depends on $Mono only.
#
Merkle: module
{
	PATH:	con "/dis/lib/merkle.dis";
	Digest:	con 32;

	# leaf hashes "mono1\0" || name || "\0" || pk || exp(64-bit big endian)
	leaf:	fn(name: string, pk: array of byte, exp: int): array of byte;

	# root of a list of leaves (promote an unpaired node)
	root:	fn(leaves: list of array of byte): array of byte;

	# inclusion path for leaf i, bottom-up; nil marks a promoted node
	path:	fn(leaves: list of array of byte, i: int): list of array of byte;

	# recompute the root from a leaf and its path
	verify:	fn(h: array of byte, path: list of array of byte, i: int,
		   r: array of byte): int;

	# insertion index of target in the sorted leaves (binary search)
	insert:	fn(leaves: list of array of byte, target: array of byte): int;

	# proof that target is absent: both neighbours are present and the
	# target lies strictly between them.  nil means "no neighbour".
	verifyabsent: fn(target, left: array of byte,
			lpath: list of array of byte, lidx: int,
			right: array of byte, rpath: list of array of byte,
			ridx: int, root: array of byte): int;
};
