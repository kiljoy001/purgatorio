Dp9ik: module
{
	PATH:	con "/dis/lib/dp9ik.dis";

	CHALLEN:	con 8;
	NONCELEN:	con 32;
	ANAMELEN:	con 28;
	TICKETLEN:	con 12+CHALLEN+2*ANAMELEN+NONCELEN+16;
	AUTHENTLEN:	con 12+CHALLEN+NONCELEN+16;

	Ticket: adt
	{
		num:	int;
		chal:	array of byte;
		cuid:	string;
		suid:	string;
		key:	array of byte;
	};

	Authenticator: adt
	{
		num:	int;
		chal:	array of byte;
		rand:	array of byte;
	};

	ticketpack:	fn(t: ref Ticket, key: array of byte): array of byte;
	ticketunpack:	fn(a: array of byte, key: array of byte):
				(int, ref Ticket);
	authpack:	fn(a: ref Authenticator, key: array of byte):
				array of byte;
	authunpack:	fn(a: array of byte, key: array of byte):
				(int, ref Authenticator);
	sessionsecret:	fn(rand: array of byte, ticketkey: array of byte):
				array of byte;
};
