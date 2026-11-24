implement Dp9ik;

include "dp9ik.m";
include "form1.m";
	form1: Form1;
include "authpak.m";
	authpak: Authpak;

init()
{
	if(form1 == nil)
		form1 = load Form1 Form1->PATH;
	if(authpak == nil)
		authpak = load Authpak Authpak->PATH;
	if(authpak != nil)
		authpak->init();
}

slice(a: array of byte, off, n: int): array of byte
{
	b := array[n] of byte;
	for(i := 0; i < n; i++)
		b[i] = a[off+i];
	return b;
}

putfield(a: array of byte, off, n: int, s: string)
{
	b := array of byte s;
	l := len b;
	if(l > n)
		l = n;
	for(i := 0; i < l; i++)
		a[off+i] = b[i];
}

getfield(a: array of byte, off, n: int): string
{
	b := array[n] of byte;
	for(i := 0; i < n; i++)
		b[i] = a[off+i];
	for(i = 0; i < n; i++)
		if(b[i] == byte 0)
			break;
	return string b[0:i];
}

ticketpack(t: ref Ticket, key: array of byte): array of byte
{
	init();
	if(form1 == nil || authpak == nil)
		return nil;
	if(t == nil || len t.chal != CHALLEN || len t.key != NONCELEN)
		return nil;
	p := array[CHALLEN+2*ANAMELEN+NONCELEN] of {* => byte 0};
	for(i := 0; i < CHALLEN; i++)
		p[i] = t.chal[i];
	putfield(p, CHALLEN, ANAMELEN, t.cuid);
	putfield(p, CHALLEN+ANAMELEN, ANAMELEN, t.suid);
	for(i = 0; i < NONCELEN; i++)
		p[CHALLEN+2*ANAMELEN+i] = t.key[i];
	return form1->encrypt(t.num, key, p);
}

ticketunpack(a: array of byte, key: array of byte): (int, ref Ticket)
{
	init();
	if(form1 == nil)
		return (0, nil);
	(num, p) := form1->decrypt(key, a);
	if(p == nil || len p != CHALLEN+2*ANAMELEN+NONCELEN)
		return (0, nil);
	t := ref Ticket;
	t.num = num;
	t.chal = slice(p, 0, CHALLEN);
	t.cuid = getfield(p, CHALLEN, ANAMELEN);
	t.suid = getfield(p, CHALLEN+ANAMELEN, ANAMELEN);
	t.key = slice(p, CHALLEN+2*ANAMELEN, NONCELEN);
	return (len a, t);
}

authpack(a: ref Authenticator, key: array of byte): array of byte
{
	init();
	if(form1 == nil || authpak == nil)
		return nil;
	if(a == nil || len a.chal != CHALLEN || len a.rand != NONCELEN)
		return nil;
	p := array[CHALLEN+NONCELEN] of {* => byte 0};
	for(i := 0; i < CHALLEN; i++)
		p[i] = a.chal[i];
	for(i = 0; i < NONCELEN; i++)
		p[CHALLEN+i] = a.rand[i];
	return form1->encrypt(a.num, key, p);
}

authunpack(a: array of byte, key: array of byte): (int, ref Authenticator)
{
	init();
	if(form1 == nil)
		return (0, nil);
	(num, p) := form1->decrypt(key, a);
	if(p == nil || len p != CHALLEN+NONCELEN)
		return (0, nil);
	t := ref Authenticator;
	t.num = num;
	t.chal = slice(p, 0, CHALLEN);
	t.rand = slice(p, CHALLEN, NONCELEN);
	return (len a, t);
}

sessionsecret(rand: array of byte, ticketkey: array of byte): array of byte
{
	init();
	if(authpak == nil)
		return nil;
	if(len rand != 2*NONCELEN || len ticketkey != NONCELEN)
		return nil;
	return authpak->hkdf(rand, array of byte "Plan 9 session secret",
	                     ticketkey, 256);
}
