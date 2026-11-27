implement Authproto;

# currently includes p9sk1

include "sys.m";
	sys: Sys;
	Rread, Rwrite: import Sys;

include "draw.m";

include "keyring.m";
	kr: Keyring;

include "auth9.m";
	auth9: Auth9;
	ANAMELEN, AERRLEN, DOMLEN, DESKEYLEN, CHALLEN, SECRETLEN: import Auth9;
	TICKREQLEN, TICKETLEN, AUTHENTLEN: import Auth9;
	AuthOK, AuthOKvar, AuthErr, AuthTreq, AuthPAK: import Auth9;
	AuthTs, AuthTc, AuthAs, AuthAc: import Auth9;
	Ticketreq, Ticket, Authenticator: import auth9;

include "authpak.m";
	authpak: Authpak;

include "dp9ik.m";
	dp9ik: Dp9ik;

include "../authio.m";
	authio: Authio;
	Aattr, Aval, Aquery: import Authio;
	Attr, IO, Key, Authinfo: import authio;
	netmkaddr, eqbytes, memrandom: import authio;

include "encoding.m";
	base16: Encoding;

Debug: con 0;

# init, addkey, closekey, write, read, close, keyprompt

init(f: Authio): string
{
	authio = f;
	sys = load Sys Sys->PATH;
	kr = load Keyring Keyring->PATH;
	auth9 = load Auth9 Auth9->PATH;
	auth9->init();
	authpak = load Authpak Authpak->PATH;
	if(authpak == nil)
		return "p9any: cannot load Authpak";
	authpak->init();
	dp9ik = load Dp9ik Dp9ik->PATH;
	if(dp9ik == nil)
		return "p9any: cannot load Dp9ik";
	base16 = load Encoding Encoding->BASE16PATH;
	return nil;
}

version := 1;

interaction(attrs: list of ref Attr, io: ref IO): string
{
	role := authio->lookattrval(attrs, "role");
	if(role == "server")
		return p9anyserver(io, attrs);
	return p9any(io);
}

p9any(io: ref IO): string
{
	while((buf := io.read()) == nil || (n := len buf) == 0 || buf[n-1] != byte 0)
		io.toosmall(2048);
	s := string buf[0:n-1];
	if(Debug)
		sys->print("s: %q\n", s);
	(nil, flds) := sys->tokenize(s, " \t");
	if(flds != nil && len hd flds >= 2 && (hd flds)[0:2] == "v."){
		if(hd flds == "v.2"){
			version = 2;
			flds = tl flds;
			if(Debug)
				sys->print("version 2\n");
		}else
			return "p9any: unknown version";
	}
	p9dom, dpdom: string;
	for(; flds != nil; flds = tl flds){
		(nf, subf) := sys->tokenize(hd flds, "@");
		if(nf != 2)
			continue;
		if(hd subf == "dp9ik" && dpdom == nil)
			dpdom = hd tl subf;
		else if(hd subf == "p9sk1" && p9dom == nil)
			p9dom = hd tl subf;
	}
	proto, dom: string;
	if(dpdom != nil){
		proto = "dp9ik";
		dom = dpdom;
	}else if(p9dom != nil){
		proto = "p9sk1";
		dom = p9dom;
	}else
		return "p9any: unsupported protocol";
	if(Debug)
		sys->print("proto %s dom %q\n", proto, dom);
	r := array of byte (proto+" "+dom);
	w := array[len r + 1] of byte;
	w[0:] = r;
	w[len r] = byte 0;
	io.write(w, len w);
	if(version == 2){
		b := io.readn(3);
		if(b == nil || b[0] != byte 'O' || b[1] != byte 'K' || b[2] != byte 0)
			return "p9any: AS protocol botch: not OK";
		if(Debug)
			sys->print("OK\n");
	}
	if(proto == "dp9ik")
		return dp9ikclient(io, dom);
	return p9sk1client(io, dom);
}

cat(a, b: array of byte): array of byte
{
	r := array[len a + len b] of byte;
	r[0:] = a;
	r[len a:] = b;
	return r;
}

readn(fd: ref Sys->FD, n: int): array of byte
{
	b := array[n] of byte;
	off := 0;
	while(off < n){
		k := sys->read(fd, b[off:], n-off);
		if(k <= 0)
			return nil;
		off += k;
	}
	return b;
}

asrdresp(fd: ref Sys->FD, n: int): array of byte
{
	b := array[1] of byte;
	if(sys->read(fd, b, 1) != 1){
		sys->werrstr("dp9ik: AS protocol botch");
		return nil;
	}
	case int b[0] {
	AuthOK =>
		return readn(fd, n);
	AuthOKvar =>
		lb := readn(fd, 5);
		if(lb == nil)
			break;
		n = int string lb;
		if(n <= 0 || n > 4096)
			break;
		return readn(fd, n);
	AuthErr =>
		eb := readn(fd, 64);
		if(eb == nil)
			break;
		for(i := 0; i < len eb && eb[i] != byte 0; i++)
			;
		sys->werrstr(sys->sprint("remote: %s", string eb[0:i]));
		return nil;
	}
	sys->werrstr("dp9ik: AS protocol botch");
	return nil;
}

delattr(attrs: list of ref Attr, name: string): list of ref Attr
{
	r: list of ref Attr;
	for(l := attrs; l != nil; l = tl l)
		if((hd l).name != name)
			r = hd l :: r;
	return r;
}

p9anyserver(io: ref IO, attrs: list of ref Attr): string
{
	# proto=p9any is the negotiator, not the sub-protocol
	sattrs := delattr(attrs, "proto");
	(keys, diag) := io.findkeys(sattrs, "proto=dp9ik dom?");
	if(keys == nil)
		return "p9any: no dp9ik server keys: "+diag;
	s := "v.2";
	for(l := keys; l != nil; l = tl l){
		d := authio->lookattrval((hd l).attrs, "dom");
		if(d != nil)
			s += " dp9ik@"+d;
	}
	if(s == "v.2")
		return "p9any: no dp9ik domains";
	b := array[len s + 1] of byte;
	b[0:] = array of byte s;
	b[len s] = byte 0;
	if(io.write(b, len b) != len b)
		return sys->sprint("p9any: can't write protocol list: %r");
	while((buf := io.read()) == nil || (n := len buf) == 0 || buf[n-1] != byte 0)
		io.toosmall(2048);
	(nil, flds) := sys->tokenize(string buf[0:n-1], " \t");
	if(flds == nil || len flds != 2 || hd flds != "dp9ik")
		return "p9any: unsupported protocol";
	dom := hd tl flds;
	ok := array[3] of byte;
	ok[0] = byte 'O';
	ok[1] = byte 'K';
	ok[2] = byte 0;
	if(io.write(ok, len ok) != len ok)
		return sys->sprint("p9any: can't write OK: %r");

	(mykey, kdiag) := io.findkey(sattrs,
		sys->sprint("proto=dp9ik dom=%q user?", dom));
	if(mykey == nil)
		return "p9any: can't find server key: "+kdiag;
	user := authio->lookattrval(mykey.attrs, "user");
	if(user == nil)
		return "p9any: server key has no user";
	(pakhash, kerr) := keypakhash(mykey, user);
	if(pakhash == nil)
		return "p9any: "+kerr;

	cchal := io.readn(CHALLEN);
	if(cchal == nil)
		return sys->sprint("p9any: can't read client challenge: %r");

	(pstate, sy) := authpak->paknew(pakhash, 1);
	if(pstate == nil)
		return "p9any: cannot make AuthPAK value";
	tr := ref Ticketreq;
	tr.rtype = AuthPAK;
	tr.authid = user;
	tr.authdom = dom;
	tr.chal = array[CHALLEN] of byte;
	memrandom(tr.chal, len tr.chal);
	tr.hostid = "";
	tr.uid = "";
	pkt := cat(tr.pack(), sy);
	if(io.write(pkt, len pkt) != len pkt)
		return sys->sprint("p9any: can't write PAK request: %r");

	hostY := io.readn(Authpak->PAKYLEN);
	if(hostY == nil)
		return sys->sprint("p9any: can't read host PAK value: %r");
	pakkey := authpak->pakfinish(pstate, hostY);
	if(pakkey == nil)
		return "p9any: AuthPAK failed";

	tb := io.readn(Dp9ik->TICKETLEN + Dp9ik->AUTHENTLEN);
	if(tb == nil)
		return sys->sprint("p9any: can't read ticket: %r");
	(nil, ts) := dp9ik->ticketunpack(tb[0:Dp9ik->TICKETLEN], pakkey);
	if(ts == nil || ts.num != AuthTs || !eqbytes(ts.chal, tr.chal))
		return "p9any: invalid server ticket";
	(nil, ta) := dp9ik->authunpack(tb[Dp9ik->TICKETLEN:], ts.key);
	if(ta == nil || ta.num != AuthAc || !eqbytes(ta.chal, tr.chal))
		return "p9any: invalid client authenticator";

	srand := array[Dp9ik->NONCELEN] of byte;
	memrandom(srand, len srand);
	sa := ref Dp9ik->Authenticator;
	sa.num = AuthAs;
	sa.chal = cchal;
	sa.rand = srand;
	sb := dp9ik->authpack(sa, ts.key);
	if(sb == nil)
		return "p9any: cannot make authenticator";
	if(io.write(sb, len sb) != len sb)
		return sys->sprint("p9any: can't write authenticator: %r");
	secret := dp9ik->sessionsecret(cat(ta.rand, srand), ts.key);
	if(secret == nil)
		return "p9any: cannot derive session secret";
	io.done(ref Authinfo(ts.cuid, ts.suid, nil, secret));
	return nil;
}

keypakhash(k: ref Key, user: string): (array of byte, string)
{
	aes: array of byte;
	if((a := authio->lookattrval(k.secrets, "!hex")) != nil){
		aes = base16->dec(a);
		if(len aes != 16)
			return (nil, "invalid !hex key");
	}else if((a = authio->lookattrval(k.secrets, "!password")) != nil)
		aes = authpak->aeskey(a);
	else
		return (nil, "no !password (or !hex) in key");
	ph := authpak->hash(aes, user);
	if(ph == nil)
		return (nil, "cannot derive AuthPAK hash");
	return (ph, nil);
}

#dp9ik client:
#	C->S:	challenge
#	S->C:	ticketreq[PAK] + server-Y
#	C->A:	ticketreq[PAK] + server-Y + client-Y
#	A->C:	host-Y + user-Y
#	C->S:	host-Y
#	C->A:	ticketreq[Treq]
#	A->C:	client ticket + server ticket
#	C->S:	server ticket + authenticator
#	S->C:	authenticator
dp9ikclient(io: ref IO, udom: string): string
{
	cchal := array[CHALLEN] of byte;
	memrandom(cchal, CHALLEN);
	if(io.write(cchal, len cchal) != len cchal)
		return sys->sprint("dp9ik: can't write challenge: %r");

	pakreq := io.readn(TICKREQLEN + Authpak->PAKYLEN);
	if(pakreq == nil)
		return sys->sprint("dp9ik: can't read PAK request: %r");
	(nil, tr) := Ticketreq.unpack(pakreq[0:TICKREQLEN]);
	if(tr == nil)
		return "dp9ik: can't unpack ticket request";
	serviceY := pakreq[TICKREQLEN:];

	(mykey, diag) := io.findkey(nil,
		sys->sprint("dom=%q proto=dp9ik user?", udom));
	if(mykey == nil)
		return "can't find key: "+diag;

	user := authio->lookattrval(mykey.attrs, "user");
	if(user == nil)
		user = authio->user();
	(pakhash, kerr) := keypakhash(mykey, user);
	if(pakhash == nil)
		return "dp9ik: "+kerr;
	(pstate, cy) := authpak->paknew(pakhash, 1);
	if(pstate == nil)
		return "dp9ik: cannot make AuthPAK value";

	tr.rtype = AuthPAK;
	tr.hostid = user;
	tr.uid = user;
	afd := authdial(nil, tr.authdom);
	if(afd == nil)
		return sys->sprint("dp9ik: can't dial auth server: %r");
	pkt := tr.pack();
	if(sys->write(afd, pkt, len pkt) != len pkt ||
	   sys->write(afd, serviceY, len serviceY) != len serviceY ||
	   sys->write(afd, cy, len cy) != len cy)
		return sys->sprint("dp9ik: can't write AuthPAK: %r");
	asbuf := asrdresp(afd, 2*Authpak->PAKYLEN);
	if(asbuf == nil)
		return sys->sprint("dp9ik: can't read AuthPAK reply: %r");
	hostY := asbuf[0:Authpak->PAKYLEN];
	userY := asbuf[Authpak->PAKYLEN:];
	pakkey := authpak->pakfinish(pstate, userY);
	if(pakkey == nil)
		return "dp9ik: AuthPAK failed";

	tr.rtype = AuthTreq;
	pkt = tr.pack();
	if(sys->write(afd, pkt, len pkt) != len pkt)
		return sys->sprint("dp9ik: can't write ticket request: %r");
	tbuf := asrdresp(afd, 2*Dp9ik->TICKETLEN);
	if(tbuf == nil)
		return sys->sprint("dp9ik: can't read tickets: %r");
	(nil, ct) := dp9ik->ticketunpack(tbuf[0:Dp9ik->TICKETLEN], pakkey);
	if(ct == nil || ct.num != AuthTc)
		return "dp9ik: invalid client ticket";
	serverbits := tbuf[Dp9ik->TICKETLEN:2*Dp9ik->TICKETLEN];

	ar := ref Dp9ik->Authenticator;
	ar.num = AuthAc;
	ar.chal = tr.chal;
	ar.rand = array[Dp9ik->NONCELEN] of byte;
	memrandom(ar.rand, len ar.rand);
	ab := dp9ik->authpack(ar, ct.key);
	if(ab == nil)
		return "dp9ik: cannot make authenticator";

	if(io.write(hostY, len hostY) != len hostY)
		return sys->sprint("dp9ik: can't write host PAK value: %r");
	sb := cat(serverbits, ab);
	if(io.write(sb, len sb) != len sb)
		return sys->sprint("dp9ik: can't write ticket: %r");

	rbuf := io.readn(Dp9ik->AUTHENTLEN);
	if(rbuf == nil)
		return sys->sprint("dp9ik: can't read server authenticator: %r");
	(nil, sa) := dp9ik->authunpack(rbuf, ct.key);
	if(sa == nil || sa.num != AuthAs || !eqbytes(sa.chal, cchal))
		return "dp9ik: invalid server authenticator";

	secret := dp9ik->sessionsecret(cat(ar.rand, sa.rand), ct.key);
	if(secret == nil)
		return "dp9ik: cannot derive session secret";
	io.done(ref Authinfo(ct.cuid, ct.suid, nil, secret));
	return nil;
}

#p9sk1:
#	C->S:	nonce-C
#	S->C:	nonce-S, uid-S, domain-S
#	C->A:	nonce-S, uid-S, domain-S, uid-C, factotum-C
#	A->C:	Kc{nonce-S, uid-C, uid-S, Kn}, Ks{nonce-S, uid-C, uid-S, K-n}
#	C->S:	Ks{nonce-S, uid-C, uid-S, K-n}, Kn{nonce-S, counter}
#	S->C:	Kn{nonce-C, counter}

#asserts that uid-S and uid-C share new secret Kn
#increment the counter to reuse the ticket.

p9sk1client(io: ref IO, udom: string): string
{

	#	C->S:	nonce-C
	cchal := array[CHALLEN] of byte;
	memrandom(cchal, CHALLEN);
	if(io.write(cchal, len cchal) != len cchal)
		return sys->sprint("p9sk1: can't write cchal: %r");

	#	S->C:	nonce-S, uid-S, domain-S
	trbuf := io.readn(TICKREQLEN);
	if(trbuf == nil)
		return sys->sprint("p9sk1: can't read ticketreq: %r");

	(nil, tr) := Ticketreq.unpack(trbuf);
	if(tr == nil)
		return "p9sk1: can't unpack ticket request";
	if(Debug)
		sys->print("ticketreq: type=%d authid=%q authdom=%q chal= hostid=%q uid=%q\n",
			tr.rtype, tr.authid, tr.authdom, tr.hostid, tr.uid);

	(mykey, diag) := io.findkey(nil, sys->sprint("dom=%q proto=p9sk1 user? !password?", udom));
	if(mykey == nil)
		return "can't find key: "+diag;
	ukey: array of byte;
	if((a := authio->lookattrval(mykey.secrets, "!hex")) != nil){
		ukey = base16->dec(a);
		if(len ukey != DESKEYLEN)
			return "p9sk1: invalid !hex key";
	}else	if((a = authio->lookattrval(mykey.secrets, "!password")) != nil)
		ukey = auth9->passtokey(a);
	else
		return "no !password (or !hex) in key";

	#	A->C:	Kc{nonce-S, uid-C, uid-S, Kn}, Ks{nonce-S, uid-C, uid-S, K-n}
	user := authio->lookattrval(mykey.attrs, "user");
	if(user == nil)
		user = authio->user();	# shouldn't happen
	tr.rtype = Auth9->AuthTreq;
	tr.hostid = user;
	tr.uid = tr.hostid;	# not speaking for anyone else
	(tick, serverbits) := getastickets(tr, ukey);
	if(tick == nil)
		return sys->sprint("p9sk1: getasticket failed: %r");
	if(tick.num != Auth9->AuthTc)
		return "p9sk1: getasticket: failed: wrong key?";
	if(Debug)
		sys->print("ticket: num=%d chal= cuid=%q suid=%q key=\n", tick.num, tick.cuid, tick.suid);

	#	C->S:	Ks{nonce-S, uid-C, uid-S, K-n}, Kn{nonce-S, counter}
	ar := ref Authenticator;
	ar.num = Auth9->AuthAc;
	ar.chal = tick.chal;
	ar.id = 0;
	obuf := array[TICKETLEN+AUTHENTLEN] of byte;
	obuf[0:] = serverbits;
	obuf[TICKETLEN:] = ar.pack(tick.key);
	if(io.write(obuf, len obuf) != len obuf)
		return "p9sk1: error writing authenticator: %r";

	#	S->C:	Kn{nonce-C, counter}
	sbuf := io.readn(AUTHENTLEN);
	if(sbuf == nil)
		return sys->sprint("p9sk1: can't read server's authenticator: %r");
	(nil, ar) = Authenticator.unpack(sbuf, tick.key);
	if(ar.num != Auth9->AuthAs || !eqbytes(ar.chal, cchal) || ar.id != 0)
		return "invalid authenticator from server";

	ai := ref Authinfo(tick.cuid, tick.suid, nil, auth9->des56to64(tick.key));
	io.done(ai);

	return nil;
}

getastickets(tr: ref Ticketreq, key: array of byte): (ref Ticket, array of byte)
{
	afd := authdial(nil, tr.authdom);
	if(afd == nil)
		return (nil, nil);
	return auth9->_asgetticket(afd, tr, key);
}

#
# where to put the following functions?
#

csgetvalue(netroot: string, keytag: string, keyval: string, needtag: string): string
{
	cs := "/net/cs";
	if(netroot != nil)
		cs = netroot+"/cs";
	fd := sys->open(cs, Sys->ORDWR);	# TO DO: choice of root
	if(fd == nil)
		return nil;
	if(sys->fprint(fd, "!%s=%s %s=*", keytag, keyval, needtag) < 0)
		return nil;
	sys->seek(fd, big 0, 0);
	buf := array[1024] of byte;
	while((n := sys->read(fd, buf, len buf)) > 0){
		al := authio->parseline(string buf[0:n]);	# assume the conventions match factotum's
		for(; al != nil; al = tl al)
			if((hd al).name == needtag)
				return (hd al).val;
	}
	return nil;
}

authdial(netroot: string, dom: string): ref Sys->FD
{
	p: string;
	if(dom != nil){
		# look up an auth server in an authentication domain
		p = csgetvalue(netroot, "authdom", dom, "auth");

		# if that didn't work, just try the IP domain
		if(p == nil)
			p = csgetvalue(netroot, "dom", dom, "auth");
		if(p == nil)
			p = "$auth";	# temporary ...
		if(p == nil){
			sys->werrstr("no auth server found for "+dom);
			return nil;
		}
	}else
		p = "$auth";	# look for one relative to my machine
	(nil, conn) := sys->dial(netmkaddr(p, netroot, "ticket"), nil);
	return conn.dfd;
}

keycheck(nil: ref Authio->Key): string
{
	return nil;
}
