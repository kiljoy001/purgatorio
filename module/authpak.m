Authpak: module
{
	PATH:	con "/dis/lib/authpak.dis";

	PAKSLEN:	con (448+7)/8;	# ed448 scalar/field element
	PAKYLEN:	con PAKSLEN;	# decaf-encoded public value
	PAKXLEN:	con PAKSLEN;	# secret scalar
	PAKPLEN:	con 4*PAKSLEN;	# extended point X,Y,Z,T
	PAKHASHLEN:	con 2*PAKPLEN;	# PM and PN
	PAKKEYLEN:	con 32;		# shared key

	PAKstate: adt
	{
		x:	array of byte;
		y:	array of byte;
		pakhash:	array of byte;
		isclient:	int;
	};

	init:		fn();
	aeskey:		fn(pw: string): array of byte;
	hash:		fn(aeskey: array of byte, user: string): array of byte;
	paknew:		fn(pakhash: array of byte, isclient: int):
				(ref PAKstate, array of byte);
	pakfinish:	fn(state: ref PAKstate, peer: array of byte): array of byte;
	hkdf:		fn(salt: array of byte, info: array of byte,
			   ikm: array of byte, n: int): array of byte;
};
