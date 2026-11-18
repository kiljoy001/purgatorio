implement Monoauthtest;

#
# monoauthtest -- loopback conformance test for monoauth(8)
#
#	monoauthtest serverkey [clientkey [port]]
#
# Starts a listener on 127.0.0.1, connects to it and runs a mono
# handshake with the given identity files.  It prints PASS when the
# encrypted round trip works and the peer names match, and FAIL
# otherwise, so a provisioning script can gate on it.
#
# Cases worth running:
#
#	same file twice			pass
#	one file with another path	fail (scope mismatch)
#	keydb/monoca absent, box/ path	pass (fail-closed box/ scope)
#	keydb/monoca absent, svc path	fail (no epoch proof)
#	stale or tampered epoch		fail (proof does not verify)
#

include "sys.m";
	sys: Sys;

include "draw.m";

include "dial.m";
	dial: Dial;

include "monoauth.m";
	mo: Monoauth;

Monoauthtest: module
{
	init:	fn(nil: ref Draw->Context, args: list of string);
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	dial = load Dial Dial->PATH;
	mo = load Monoauth Monoauth->PATH;
	if(dial == nil || mo == nil){
		sys->print("FAIL: cannot load monoauth\n");
		return;
	}
	args = tl args;
	if(args == nil){
		sys->print("usage: monoauthtest serverkey [clientkey [port]]\n");
		return;
	}
	skey := hd args;
	ckey := skey;
	if(tl args != nil)
		ckey = hd tl args;
	port := "5758";
	if(tl args != nil && tl tl args != nil)
		port = hd tl tl args;
	addr := "tcp!127.0.0.1!" + port;

	# announce does not accept: listen blocks until a call arrives, so
	# the server side has to wait in its own process while we connect.
	c := dial->announce(addr);
	if(c == nil){
		sys->print("FAIL: announce: %r\n");
		return;
	}
	res := chan[2] of string;
	spawn srvproc(c, skey, res);

	cli := dial->dial(addr, nil);
	if(cli == nil){
		sys->print("FAIL: dial: %r\n");
		return;
	}
	(sfd, cname) := mo->client(ckey, cli.dfd);
	if(sfd == nil){
		sys->print("FAIL: client: %s\n", cname);
		return;
	}
	msg := array of byte "ping\n";
	if(sys->write(sfd, msg, len msg) != len msg){
		sys->print("FAIL: write: %r\n");
		return;
	}
	buf := array[64] of byte;
	n := sys->read(sfd, buf, len buf);
	if(n <= 0){
		sys->print("FAIL: read: %r\n");
		return;
	}
	got := string buf[0:n];
	r := <-res;
	sys->print("client sees %s, server sees %s\n", cname, r);
	if(got == "pong\n" && r == cname)
		sys->print("PASS\n");
	else{
		sys->print("client got %q\n", got);
		sys->print("FAIL\n");
	}
}

srvproc(c: ref Dial->Connection, key: string, res: chan of string)
{
	l := dial->listen(c);
	if(l == nil){
		res <-= "listen failed";
		return;
	}
	fd := dial->accept(l);
	if(fd == nil){
		res <-= "accept failed";
		return;
	}
	(sfd, sname) := mo->server(key, fd);
	if(sfd == nil){
		fd = nil;		# close, so the peer does not hang
		res <-= "server: " + sname;
		return;
	}
	buf := array[64] of byte;
	n := sys->read(sfd, buf, len buf);
	if(n <= 0){
		res <-= "read failed";
		return;
	}
	sys->write(sfd, array of byte "pong\n", 5);
	res <-= sname;
}
