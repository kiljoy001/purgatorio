#include	"dat.h"
#include	"fns.h"
#include	"error.h"
#include	"ip.h"

enum
{
	Qtopdir		= 1,	/* top level directory */
	Qtopbase,
	Qarp=	Qtopbase,
/*	Qiproute, */
/*	Qipselftab,	*/
	Qndb,

	Qprotodir,		/* directory for a protocol */
	Qprotobase,
	Qclone=	Qprotobase,
	Qstats,

	Qconvdir,		/* directory for a conversation */
	Qconvbase,
	Qctl=	Qconvbase,
	Qdata,
	Qlisten,
	Qlocal,
	Qremote,
	Qstatus,

	Logtype=	5,
	Masktype=	(1<<Logtype)-1,
	Logconv=	12,
	Maskconv=	(1<<Logconv)-1,
	Shiftconv=	Logtype,
	Logproto=	8,
	Maskproto=	(1<<Logproto)-1,
	Shiftproto=	Logtype + Logconv,

	Statelen = 256,

	Nfs=	1,

	Maxproto	= 4,
	MAXCONV		= 4096
};
#define TYPE(x) 	( ((ulong)(x).path) & Masktype )
#define CONV(x) 	( (((ulong)(x).path) >> Shiftconv) & Maskconv )
#define PROTO(x) 	( (((ulong)(x).path) >> Shiftproto) & Maskproto )
#define QID(p, c, y) 	( ((p)<<(Shiftproto)) | ((c)<<Shiftconv) | (y) )

enum
{
	Idle=		0,
	Announcing=	1,
	Announced=	2,
	Connecting=	3,
	Connected=	4,
	Hungup=	5,
};

struct Conv
{
	QLock	l;

	int	x;	/* conversation index */
	Proto*	p;

	uchar	laddr[IPaddrlen];	/* local IP address */
	uchar	raddr[IPaddrlen];	/* remote IP address */
	int	restricted;	/* remote port is restricted */
	ushort	lport;	/* local port number */
	ushort	rport;	/* remote port number */

	char*	owner;	/* protections */
	int	perm;
	int	inuse;	/* opens of listen/data/ctl */
	int	state;

	/* udp specific */
	int	headers;	/* data src/dst headers in udp */

	char	cerr[ERRMAX];

	QLock	listenq;

	void*	ptcl;	/* protocol specific stuff */

	int	sfd;
	QLock	wlock;	/* prevent data from being split by concurrent writes */
};

struct Proto
{
	QLock	l;
	int	x;
	int	ipproto;
	int	stype;
	char*	name;
	int	maxconv;
	Fs*	f;	/* file system this proto is part of */
	Conv**	conv;	/* array of conversations */
	int	pctlsize;	/* size of per protocol ctl block */
	int	nc;	/* number of conversations */
	int	ac;
	Qid	qid;	/* qid for protocol directory */
	/* port allocation isn't done here when hosted */

	void*	priv;
};

/*
 * one per IP protocol stack
 */
struct Fs
{
	RWlock	l;
	int	dev;

	int	np;
	Proto*	p[Maxproto+1];	/* list of supported protocols */
	Proto*	t2p[256];	/* vector of all protocols */

	char	ndb[1024];	/* an ndb entry for this interface */
	int	ndbvers;
	long	ndbmtime;
};

static	Fs	*ipfs[Nfs];	/* attached fs's */
static	char	network[] = "network";
static	char* ipstates[] = {
	"Closed",	/* Idle */
	"Announcing",
	"Announced",
	"Connecting",
	"Established",	/* Connected */
	"Closed",	/* Hungup */
};

static	Conv*	protoclone(Proto*, char*, int);
static	Conv*	newconv(Proto*, Conv **);
static	void	setladdr(Conv*);

extern int	qpassnolim(Queue*, Block*);

/* Native IL servers coexist with the emu stack on the same host.
 * The kernel rejects an unlistened SYNC with CLOSE; doing that here
 * would reject a port owned by a native server before it can answer.
 * Leave rejection off so unknown ports simply time out. */
static	int	ilrejectenabled;

static	Conv*	ilaccept(Conv*);
static	long	ilreadq(Conv*, void*, long);
static	long	ilwriteq(Conv*, void*, long);
static	void	ilctlmsg(Proto*, Conv*, Cmdbuf*);
static	void	ilcloseconv(Conv*);
static	void	ilstatus(Conv*, char*, int);

static int
ip3gen(Chan *c, int i, Dir *dp)
{
	Qid q;
	Conv *cv;
	char *p;

	cv = ipfs[c->dev]->p[PROTO(c->qid)]->conv[CONV(c->qid)];
	if(cv->owner == nil)
		kstrdup(&cv->owner, eve);
	mkqid(&q, QID(PROTO(c->qid), CONV(c->qid), i), 0, QTFILE);

	switch(i) {
	default:
		return -1;
	case Qctl:
		devdir(c, q, "ctl", 0, cv->owner, cv->perm, dp);
		return 1;
	case Qdata:
		devdir(c, q, "data", 0, cv->owner, cv->perm, dp);
		return 1;
	case Qlisten:
		devdir(c, q, "listen", 0, cv->owner, cv->perm, dp);
		return 1;
	case Qlocal:
		p = "local";
		break;
	case Qremote:
		p = "remote";
		break;
	case Qstatus:
		p = "status";
		break;
	}
	devdir(c, q, p, 0, cv->owner, 0444, dp);
	return 1;
}

static int
ip2gen(Chan *c, int i, Dir *dp)
{
	Qid q;

	switch(i) {
	case Qclone:
		mkqid(&q, QID(PROTO(c->qid), 0, Qclone), 0, QTFILE);
		devdir(c, q, "clone", 0, network, 0666, dp);
		return 1;
	case Qstats:
		mkqid(&q, QID(PROTO(c->qid), 0, Qstats), 0, QTFILE);
		devdir(c, q, "stats", 0, network, 0444, dp);
		return 1;
	}	
	return -1;
}

static int
ip1gen(Chan *c, int i, Dir *dp)
{
	Qid q;
	char *p;
	int prot;
	int len = 0;
	Fs *f;
	extern ulong	kerndate;

	f = ipfs[c->dev];

	prot = 0664;
	mkqid(&q, QID(0, 0, i), 0, QTFILE);
	switch(i) {
	default:
		return -1;
	case Qarp:
		p = "arp";
		break;
	case Qndb:
		p = "ndb";
		len = strlen(ipfs[c->dev]->ndb);
		break;
/*	case Qiproute:
		p = "iproute";
		break;
	case Qipselftab:
		p = "ipselftab";
		prot = 0444;
		break;
	case Qiprouter:
		p = "iprouter";
		break;
	case Qlog:
		p = "log";
		break;
*/
	}
	devdir(c, q, p, len, network, prot, dp);
	if(i == Qndb && f->ndbmtime > kerndate)
		dp->mtime = f->ndbmtime;
	return 1;
}

static int
ipgen(Chan *c, char *name, Dirtab *tab, int x, int s, Dir *dp)
{
	Qid q;
	Conv *cv;
	Fs *f;

	USED(name);
	USED(tab);
	USED(x);
	f = ipfs[c->dev];

	switch(TYPE(c->qid)) {
	case Qtopdir:
		if(s == DEVDOTDOT){
			mkqid(&q, QID(0, 0, Qtopdir), 0, QTDIR);
			sprint(up->genbuf, "#I%lud", c->dev);
			devdir(c, q, up->genbuf, 0, network, 0555, dp);
			return 1;
		}
		if(s < f->np) {
/*			if(f->p[s]->connect == nil)
				return 0;	/* protocol with no user interface */
			mkqid(&q, QID(s, 0, Qprotodir), 0, QTDIR);
			devdir(c, q, f->p[s]->name, 0, network, 0555, dp);
			return 1;
		}
		s -= f->np;
		return ip1gen(c, s+Qtopbase, dp);
	case Qarp:
	case Qndb:
/*	case Qiproute:
	case Qiprouter:
	case Qipselftab:	*/
		return ip1gen(c, TYPE(c->qid), dp);
	case Qprotodir:
		if(s == DEVDOTDOT){
			mkqid(&q, QID(0, 0, Qtopdir), 0, QTDIR);
			sprint(up->genbuf, "#I%lud", c->dev);
			devdir(c, q, up->genbuf, 0, network, 0555, dp);
			return 1;
		}
		if(s < f->p[PROTO(c->qid)]->ac) {
			cv = f->p[PROTO(c->qid)]->conv[s];
			sprint(up->genbuf, "%d", s);
			mkqid(&q, QID(PROTO(c->qid), s, Qconvdir), 0, QTDIR);
			devdir(c, q, up->genbuf, 0, cv->owner, 0555, dp);
			return 1;
		}
		s -= f->p[PROTO(c->qid)]->ac;
		return ip2gen(c, s+Qprotobase, dp);
	case Qclone:
	case Qstats:
		return ip2gen(c, TYPE(c->qid), dp);
	case Qconvdir:
		if(s == DEVDOTDOT){
			s = PROTO(c->qid);
			mkqid(&q, QID(s, 0, Qprotodir), 0, QTDIR);
			devdir(c, q, f->p[s]->name, 0, network, 0555, dp);
			return 1;
		}
		return ip3gen(c, s+Qconvbase, dp);
	case Qctl:
	case Qdata:
	case Qlisten:
	case Qlocal:
	case Qremote:
	case Qstatus:
		return ip3gen(c, TYPE(c->qid), dp);
	}
	return -1;
}

static void
newproto(char *name, int type, int maxconv)
{
	Proto *p;

	p = smalloc(sizeof(*p));
	p->name = name;
	p->stype = type;
	p->ipproto = type+1;	/* temporary */
	p->nc = maxconv;
	if(Fsproto(ipfs[0], p))
		panic("can't newproto %s", name);
}

void
ipinit(void)
{
	ipfs[0] = malloc(sizeof(Fs));
	if(ipfs[0] == nil)
		panic("no memory for IP stack");

	newproto("udp", S_UDP, 64);
	newproto("tcp", S_TCP, 2048);
	newproto("il", S_IL, 64);

	fmtinstall('i', eipfmt);
	fmtinstall('I', eipfmt);
	fmtinstall('E', eipfmt);
	fmtinstall('V', eipfmt);
	fmtinstall('M', eipfmt);
}

Chan *
ipattach(char *spec)
{
	Chan *c;

	if(atoi(spec) != 0)
		error("bad specification");

	c = devattach('I', spec);
	mkqid(&c->qid, QID(0, 0, Qtopdir), 0, QTDIR);
	c->dev = 0;

	return c;
}

static Walkqid*
ipwalk(Chan* c, Chan *nc, char **name, int nname)
{
	return devwalk(c, nc, name, nname, nil, 0, ipgen);
}

static int
ipstat(Chan *c, uchar *db, int n)
{
	return devstat(c, db, n, 0, 0, ipgen);
}

static int m2p[] = {
	4,
	2,
	6,
};

static Chan *
ipopen(Chan *c, int omode)
{
	Conv *cv, *nc;
	Proto *p;
	uchar raddr[IPaddrlen];
	ushort rport;
	int perm, sfd;
	Fs *f;

	perm = m2p[omode&3];

	f = ipfs[c->dev];

	switch(TYPE(c->qid)) {
	default:
		break;
	case Qtopdir:
	case Qprotodir:
	case Qconvdir:
	case Qstatus:
	case Qremote:
	case Qlocal:
	case Qstats:
	/* case Qipselftab: */
		if(omode != OREAD)
			error(Eperm);
		break;
	case Qndb:
		if(omode & (OWRITE|OTRUNC) && !iseve())
			error(Eperm);
		if((omode & (OWRITE|OTRUNC)) == (OWRITE|OTRUNC)){
			f->ndb[0] = 0;
			f->ndbvers++;
		}
		break;
	case Qclone:
		p = f->p[PROTO(c->qid)];
		cv = protoclone(p, up->env->user, -1);
		if(cv == 0)
			error(Enodev);
		mkqid(&c->qid, QID(p->x, cv->x, Qctl), 0, QTFILE);
		break;
	case Qdata:
	case Qctl:
		p = f->p[PROTO(c->qid)];
		qlock(&p->l);
		cv = p->conv[CONV(c->qid)];
		qlock(&cv->l);
		if(waserror()){
			qunlock(&cv->l);
			qunlock(&p->l);
			nexterror();
		}
		if((perm & (cv->perm>>6)) != perm) {
			if(strcmp(up->env->user, cv->owner) != 0)
				error(Eperm);
			if((perm & cv->perm) != perm)
				error(Eperm);
		}
		cv->inuse++;
		if(cv->inuse == 1) {
			kstrdup(&cv->owner, up->env->user);
			cv->perm = 0660;
			if(cv->sfd < 0){
				if(p->stype == S_IL)
					cv->sfd = -2;
				else
					cv->sfd = so_socket(p->stype);
			}
		}
		poperror();
		qunlock(&cv->l);
		qunlock(&p->l);
		break;
	case Qlisten:
		p = f->p[PROTO(c->qid)];
		cv = p->conv[CONV(c->qid)];
		if((perm & (cv->perm>>6)) != perm){
			if(strcmp(up->env->user, cv->owner) != 0)
				error(Eperm);
			if((perm & cv->perm) != perm)
				error(Eperm);
		}

		if(p->stype == S_IL){
			nc = ilaccept(cv);
			mkqid(&c->qid, QID(PROTO(c->qid), nc->x, Qctl), 0, QTFILE);
			break;
		}

		if(cv->state != Announced)
			error("not announced");

		qlock(&cv->listenq);
		if(waserror()){
			qunlock(&cv->listenq);
			nexterror();
		}

		sfd = so_accept(cv->sfd, raddr, &rport);

		nc = protoclone(p, up->env->user, sfd);
		if(nc == 0) {
			so_close(sfd);
			error(Enodev);
		}
		memmove(nc->raddr, raddr, IPaddrlen);
		nc->rport = rport;
		setladdr(nc);
		nc->state = Connected;
		mkqid(&c->qid, QID(PROTO(c->qid), nc->x, Qctl), 0, QTFILE);

		poperror();
		qunlock(&cv->listenq);
		break;
	}
	c->mode = openmode(omode);
	c->flag |= COPEN;
	c->offset = 0;
	return c;
}

static void
closeconv(Conv *cv)
{
	int fd;

	qlock(&cv->l);

	if(--cv->inuse > 0) {
		qunlock(&cv->l);
		return;
	}

	if(waserror()){
		qunlock(&cv->l);
		return;
	}
	kstrdup(&cv->owner, network);
	cv->perm = 0660;
	if(cv->p->stype == S_IL)
		ilcloseconv(cv);
	cv->state = Idle;
	cv->restricted = 0;
	fd = cv->sfd;
	cv->sfd = -1;
	if(fd >= 0)
		so_close(fd);
	poperror();
	qunlock(&cv->l);
}

static void
ipclose(Chan *c)
{
	Fs *f;

	f = ipfs[c->dev];
	switch(TYPE(c->qid)) {
	case Qdata:
	case Qctl:
		if(c->flag & COPEN)
			closeconv(f->p[PROTO(c->qid)]->conv[CONV(c->qid)]);
		break;
	}
}

static long
ipread(Chan *ch, void *a, long n, vlong off)
{
	int r;
	Conv *c;
	Proto *x;
	char *p, *s;
	Fs *f;
	ulong offset = off;

	f = ipfs[ch->dev];

	p = a;
	switch(TYPE(ch->qid)) {
	default:
		error(Eperm);
	case Qprotodir:
	case Qtopdir:
	case Qconvdir:
		return devdirread(ch, a, n, 0, 0, ipgen);
	case Qarp:
		error(Eperm);	/* TO DO */
	case Qndb:
		return readstr(off, a, n, f->ndb);
	case Qctl:
		sprint(up->genbuf, "%lud", CONV(ch->qid));
		return readstr(offset, p, n, up->genbuf);
	case Qremote:
		x = f->p[PROTO(ch->qid)];
		c = x->conv[CONV(ch->qid)];
		sprint(up->genbuf, "%I!%d\n", c->raddr, c->rport);
		return readstr(offset, p, n, up->genbuf);
	case Qlocal:
		x = f->p[PROTO(ch->qid)];
		c = x->conv[CONV(ch->qid)];
		sprint(up->genbuf, "%I!%d\n", c->laddr, c->lport);
		return readstr(offset, p, n, up->genbuf);
	case Qstatus:
		x = f->p[PROTO(ch->qid)];
		c = x->conv[CONV(ch->qid)];
		s = smalloc(Statelen);
		if(waserror()){
			free(s);
			nexterror();
		}
		if(x->stype == S_IL)
			ilstatus(c, s, Statelen);
		else
			snprint(s, Statelen, "%s\n", ipstates[c->state]);
		n = readstr(offset, p, n, s);
		poperror();
		free(s);
		return n;
	case Qdata:
		x = f->p[PROTO(ch->qid)];
		c = x->conv[CONV(ch->qid)];
		if(x->stype == S_IL)
			return ilreadq(c, a, n);
		if(c->sfd < 0)
			error(Ehungup);
		if(c->headers) {
			if(n < c->headers)
				error(Ebadarg);
			p = a;
			r = so_recv(c->sfd, p + c->headers, n - c->headers, p, c->headers);
			if(r >= 0)
				r += c->headers;
		} else
			r = so_recv(c->sfd, a, n, nil, 0);
		if(r < 0)
			oserror();
		return r;
	case Qstats:
		error("stats not implemented");
		return n;
	}
}

static void
setladdr(Conv *c)
{
	/* TO DO: this can't be right for hosts with several addresses before connect/accept */
	so_getsockname(c->sfd, c->laddr, &c->lport);
}

/*
 * pick a local port and set it
 */
static void
setlport(Conv *c)
{
	uchar laddr[IPaddrlen];
	ushort p;

	so_bind(c->sfd, c->restricted, c->laddr, c->lport);
	if(c->lport == 0 || ipcmp(c->laddr, IPnoaddr) == 0){
		so_getsockname(c->sfd, laddr, &p);
		if(c->lport == 0)
			c->lport = p;
		if(ipcmp(c->laddr, IPnoaddr) == 0)
			memmove(c->laddr, laddr, sizeof laddr);
	}
}

static int
portno(char *p)
{
	long n;
	char *e;

	n = strtoul(p, &e, 0);
	if(p == e)
		error("non-numeric port number");
	return n;
}

/*
 *  set a local address and port from a string of the form
 *	[address!]port[!r]
 */
static void
setladdrport(Conv *c, char *str, int announcing)
{
	char *p;
	int lport;

	/*
	 *  ignore restricted part if it exists.  it's
	 *  meaningless on local ports.
	 */
	p = strchr(str, '!');
	if(p != nil){
		*p++ = 0;
		if(strcmp(p, "r") == 0)
			p = nil;
	}

	c->lport = 0;
	if(p == nil){
		if(announcing)
			ipmove(c->laddr, IPnoaddr);
		else if(0)
			setladdr(c);
		p = str;
	} else {
		if(strcmp(str, "*") == 0)
			ipmove(c->laddr, IPnoaddr);
		else if(parseip(c->laddr, str) == 0)
			error("invalid IP address");
	}

	if(announcing && strcmp(p, "*") == 0){
		if(!iseve())
			error(Eperm);
		c->lport = 0;
		setlport(c);
		return;
	}

	lport = portno(p);
	if(lport <= 0)
		c->lport = 0;
	else
		c->lport = lport;

	setlport(c);
}

static char*
setraddrport(Conv *c, char *str)
{
	char *p;

	p = strchr(str, '!');
	if(p == nil)
		return "malformed address";
	*p++ = 0;
	if(parseip(c->raddr, str) == 0)
		return "invalid IP address";
	c->rport = portno(p);
	p = strchr(p, '!');
	if(p){
		if(strstr(p, "!r") != nil)
			c->restricted = 1;
	}
	return nil;
}

static void
connectctlmsg(Proto *x, Conv *c, Cmdbuf *cb)
{
	char *p;

	USED(x);
	if(c->state != Idle)
		error(Econinuse);
	c->state = Connecting;
	c->cerr[0] = '\0';
	switch(cb->nf) {
	default:
		error("bad args to connect");
	case 2:
		p = setraddrport(c, cb->f[1]);
		if(p != nil)
			error(p);
		break;
	case 3:
		p = setraddrport(c, cb->f[1]);
		if(p != nil)
			error(p);
		c->lport = portno(cb->f[2]);
		setlport(c);
		break;
	}
	qunlock(&c->l);
	if(waserror()){
		qlock(&c->l);
		c->state = Connected;	/* sic */
		nexterror();
	}
	/* p = x->connect(c, cb->f, cb->nf); */
	so_connect(c->sfd, c->raddr, c->rport);
	qlock(&c->l);
	poperror();
	setladdr(c);
	c->state = Connected;
}

static void
announcectlmsg(Proto *x, Conv *c, Cmdbuf *cb)
{
	if(c->state != Idle)
		error(Econinuse);
	c->state = Announcing;
	c->cerr[0] = '\0';
	ipmove(c->raddr, IPnoaddr);
	c->rport = 0;
	switch(cb->nf){
	default:
		error("bad args to announce");
	case 2:
		setladdrport(c, cb->f[1], 1);
		break;
	}
	USED(x);
	/* p = x->announce(c, cb->f, cb->nf); */
	if(c->p->stype != S_UDP){
		qunlock(&c->l);
		if(waserror()){
			c->state = Announced;	/* sic */
			qlock(&c->l);
			nexterror();
		}
		so_listen(c->sfd);
		qlock(&c->l);
		poperror();
	}
	c->state = Announced;
}

static void
bindctlmsg(Proto *x, Conv *c, Cmdbuf *cb)
{
	USED(x);
	switch(cb->nf){
	default:
		error("bad args to bind");
	case 2:
		setladdrport(c, cb->f[1], 0);
		break;
	}
}

static long
ipwrite(Chan *ch, void *a, long n, vlong off)
{
	Conv *c;
	Proto *x;
	char *p;
	Cmdbuf *cb;
	Fs *f;

	f = ipfs[ch->dev];

	switch(TYPE(ch->qid)) {
	default:
		error(Eperm);
	case Qdata:
		x = f->p[PROTO(ch->qid)];
		c = x->conv[CONV(ch->qid)];
		if(x->stype == S_IL)
			return ilwriteq(c, a, n);
		if(c->sfd < 0)
			error(Ehungup);
		qlock(&c->wlock);
		if(waserror()){
			qunlock(&c->wlock);
			nexterror();
		}
		if(c->headers) {
			if(n < c->headers)
				error(Eshort);
			p = a;
			n = so_send(c->sfd, p + c->headers, n - c->headers, p, c->headers);
			if(n >= 0)
				n += c->headers;
		} else
			n = so_send(c->sfd, a, n, nil, 0);
		poperror();
		qunlock(&c->wlock);
		if(n < 0)
			oserror();
		break;
	case Qarp:
		return arpwrite(a, n);
	case Qndb:
		if(off > strlen(f->ndb))
			error(Eio);
		if(off+n >= sizeof(f->ndb)-1)
			error(Eio);
		memmove(f->ndb+off, a, n);
		f->ndb[off+n] = 0;
		f->ndbvers++;
		f->ndbmtime = seconds();
		break;
	case Qctl:
		x = f->p[PROTO(ch->qid)];
		c = x->conv[CONV(ch->qid)];
		cb = parsecmd(a, n);
		qlock(&c->l);
		if(waserror()){
			qunlock(&c->l);
			free(cb);
			nexterror();
		}
		if(cb->nf < 1)
			error("short control request");
		if(x->stype == S_IL)
			ilctlmsg(x, c, cb);
		else if(strcmp(cb->f[0], "connect") == 0)
			connectctlmsg(x, c, cb);
		else if(strcmp(cb->f[0], "announce") == 0)
			announcectlmsg(x, c, cb);
		else if(strcmp(cb->f[0], "bind") == 0)
			bindctlmsg(x, c, cb);
		else if(strcmp(cb->f[0], "ttl") == 0){
			/* ignored */
		} else if(strcmp(cb->f[0], "tos") == 0){
			/* ignored */
		} else if(strcmp(cb->f[0], "ignoreadvice") == 0){
			/* ignored */
		} else if(strcmp(cb->f[0], "headers4") == 0){
			if(c->p->stype != S_UDP)
				error(Enoctl);
			c->headers = OUdphdrlenv4;
		} else if(strcmp(cb->f[0], "oldheaders") == 0){
			if(c->p->stype != S_UDP)
				error(Enoctl);
			c->headers = OUdphdrlen;
		} else if(strcmp(cb->f[0], "headers") == 0){
			if(c->p->stype != S_UDP)
				error(Enoctl);
			c->headers = Udphdrlen;
		} else if(strcmp(cb->f[0], "hangup") == 0){
			if(c->p->stype != S_TCP)
				error(Enoctl);
			qunlock(&c->l);
			if(waserror()){
				qlock(&c->l);
				nexterror();
			}
			/* TO DO: check fd status if socket close/hangup interrupted */
			if(c->sfd >= 0 && so_hangup(c->sfd, 1) < 0)
				oserror();
			qlock(&c->l);
			poperror();
			c->sfd = -1;
			c->state = Hungup;
		} else if(strcmp(cb->f[0], "keepalive") == 0){
			if(c->p->stype != S_TCP)
				error(Enoctl);
			if(c->sfd < 0)
				error("not connected");
			so_keepalive(c->sfd, cb->nf>1? atoi(cb->f[1]): 0);
		} else
			error(Enoctl);
		poperror();
		qunlock(&c->l);
		free(cb);
		break;
	}
	return n;
}

static int
ipwstat(Chan *c, uchar *dp, int n)
{
	Dir *d;
	Conv *cv;
	Proto *p;
	Fs *f;

	f = ipfs[c->dev];
	switch(TYPE(c->qid)) {
	default:
		error(Eperm);
		break;
	case Qctl:
	case Qdata:
		break;
	}

	d = smalloc(sizeof(*d)+n);
	if(waserror()){
		free(d);
		nexterror();
	}
	n = convM2D(dp, n, d, (char*)&d[1]);
	if(n == 0)
		error(Eshortstat);
	p = f->p[PROTO(c->qid)];
	cv = p->conv[CONV(c->qid)];
	if(!iseve() && strcmp(up->env->user, cv->owner) != 0)
		error(Eperm);
	if(!emptystr(d->uid))
		kstrdup(&cv->owner, d->uid);
	if(d->mode != ~0UL)
		cv->perm = d->mode & 0777;
	poperror();
	free(d);
	return n;
}

static Conv*
protoclone(Proto *p, char *user, int nfd)
{
	Conv *c, **pp, **ep, **np;
	int maxconv;

	c = 0;
	qlock(&p->l);
	if(waserror()) {
		qunlock(&p->l);
		nexterror();
	}
	ep = &p->conv[p->nc];
	for(pp = p->conv; pp < ep; pp++) {
		c = *pp;
		if(c == 0) {
			c = newconv(p, pp);
			break;
		}
		if(canqlock(&c->l)){
			if(c->inuse == 0 && c->ptcl == nil)
				break;
			qunlock(&c->l);
		}
	}
	if(pp >= ep) {
		if(p->nc >= MAXCONV) {
			qunlock(&p->l);
			poperror();
			return 0;
		}
		maxconv = 2 * p->nc;
		if(maxconv > MAXCONV)
			maxconv = MAXCONV;
		np = realloc(p->conv, sizeof(Conv*) * maxconv);
		if(np == nil)
			error(Enomem);
		p->conv = np;
		pp = &p->conv[p->nc];
		memset(pp, 0, sizeof(Conv*)*(maxconv - p->nc));
		p->nc = maxconv;
		c = newconv(p, pp);
	}

	c->inuse = 1;
	kstrdup(&c->owner, user);
	c->perm = 0660;
	c->state = Idle;
	ipmove(c->laddr, IPnoaddr);
	ipmove(c->raddr, IPnoaddr);
	c->lport = 0;
	c->rport = 0;
	c->restricted = 0;
	c->headers = 0;
	c->sfd = nfd;
	if(nfd == -1){
		if(p->stype == S_IL)
			c->sfd = -2;
		else
			c->sfd = so_socket(p->stype);
	}

	qunlock(&c->l);
	qunlock(&p->l);
	poperror();
	return c;
}

static Conv*
newconv(Proto *p, Conv **pp)
{
	Conv *c;

	*pp = c = malloc(sizeof(Conv));
	if(c == 0)
		error(Enomem);
	memset(c, 0, sizeof(Conv));
	c->sfd = -1;
	qlock(&c->l);
	c->inuse = 1;
	c->p = p;
	c->x = pp - p->conv;
	p->ac++;
	return c;
}

int
arpwrite(char *s, int len)
{
	int n;
	char *f[4], buf[256];

	if(len >= sizeof(buf))
		len = sizeof(buf)-1;
	memmove(buf, s, len);
	buf[len] = 0;
	if(len > 0 && buf[len-1] == '\n')
		buf[len-1] = 0;

	n = getfields(buf, f, 4, 1, " ");
	if(strcmp(f[0], "add") == 0) {
		if(n == 3) {
			arpadd(f[1], f[2], n);
			return len;
		}
	}
	error("bad arp request");

	return len;
}

/*
 * IL (IP protocol 40), ported from the Harvey implementation
 * (sys/src/9/ip/il.c) to the hosted stack.  A single raw AF_INET6
 * socket carries every conversation; a receiver kproc demultiplexes
 * packets by (peer address, IL ports) and a timer kproc drives
 * retransmission, ack and keepalive timers.  Conversations expose
 * the same clone/ctl/data/listen interface as TCP and UDP, so
 * dial/announce/mount need no IL-specific code above this layer.
 */

enum
{
	Ilsync,
	Ildata,
	Ildataquery,
	Ilack,
	Ilquery,
	Ilstate,
	Ilclose,
};

enum
{
	Ilclosed,
	Ilsyncer,
	Ilsyncee,
	Ilestablished,
	Ildraining,
	Illistening,
	Ilclosing,
};

static char *ilstates[] =
{
	"Closed", "Syncer", "Syncee", "Established",
	"Draining", "Listen", "Closing",
};

enum
{
	IL_HDRSIZE	= 18,
	IL_PROTO	= 40,

	Iltickms	= 50,
	AckDelay	= 2*Iltickms,
	MaxTimeout	= 30*1000,
	QueryTime	= 10*1000,
	DeathTime	= 30*QueryTime,
	MaxRexmit	= 16,
	Defaultwin	= 20,
	Initialwin	= 2,
	Maxflight	= 32*1024,
	LogAGain	= 3,
	AGain		= 1<<LogAGain,
	LogDGain	= 2,
	DefByteRate	= 100,
	DefRtt		= 50,
	IlMaxrq		= 64*1024,
	Ilflow		= 0x80,
	Ilcreditlen	= 8,
	Nqt		= 8,

	Ilmaxmsg	= 16384,
};

typedef struct Ilhdr Ilhdr;
struct Ilhdr
{
	uchar	ilsum[2];	/* checksum of IL header plus data */
	uchar	illen[2];	/* packet length */
	uchar	iltype;		/* packet type */
	uchar	ilspec;		/* special */
	uchar	ilsrc[2];	/* src port */
	uchar	ildst[2];	/* dst port */
	uchar	ilid[4];	/* sequence id */
	uchar	ilack[4];	/* acked sequence */
};

typedef struct Ilcb Ilcb;
struct Ilcb
{
	int	state;
	Conv	*conv;
	Queue	*rq;

	QLock	ackq;		/* unacknowledged queue */
	Block	*unacked;
	Block	*unackedtail;
	ulong	unackedbytes;
	uvlong	txbytes;	/* payload bytes sent */
	uvlong	rxqueued;	/* payload bytes delivered to rq */
	uvlong	peerread;	/* peer's cumulative bytes read */
	uvlong	creditread;	/* last read count advertised */
	int	flowpeer;	/* peer advertised Ilflow on SYNC */
	Block	*pending;	/* message held while send window full */
	Block	*outq;		/* payloads waiting for ilpump */
	Block	*outqtail;
	ulong	outqbytes;
	int	flight;		/* unacknowledged messages */
	int	cwind;		/* congestion window, in messages */
	int	ssthresh;
	int	acks;
	int	inrecovery;
	ulong	recovery;

	QLock	outo;		/* out of order packet queue */
	Block	*outoforder;
	ulong	next;		/* id of next to send */
	ulong	recvd;		/* last packet received */
	ulong	acksent;	/* last packet acked */
	ulong	start;		/* local start id */
	ulong	rstart;		/* remote start id */
	int	window;		/* maximum receive window */
	int	rxquery;
	int	rxtot;
	int	rexmit;
	ulong	qt[Nqt+1];
	int	qtx;

	int	fasttimeout;

	ulong	lastxmit;
	ulong	lastrecv;
	ulong	timeout;
	ulong	acktime;
	ulong	querytime;

	int	delay;
	int	rate;
	int	mdev;
	int	maxrtt;
	ulong	rttack;
	int	rttlen;
	ulong	rttstart;	/* ms */

	/* hosted additions */
	Rendez	cr;		/* connect completion */
	Rendez	wr;		/* write space available */
	Rendez	ar;		/* accept pending (listener) */
	QLock	alock;
	Ilcb	*acceptq;
	Ilcb	*accepttail;
	Ilcb	*anext;
	Conv	*listener;
	int	waiters;
	int	convref;	/* conversation still owns this cb */
	char	err[ERRMAX];
};

typedef struct Ilpriv Ilpriv;
struct Ilpriv
{
	QLock	l;
	int	fd;		/* AF_INET6 raw socket */
	int	fd4;		/* AF_INET raw socket, or -1 */
	int	started;
	uvlong	inmsgs;
	uvlong	outmsgs;
	uvlong	csumerrs;
	uvlong	dropped;
	uvlong	rexmit;
};

static void	ilhangup(Conv*, char*);
static void	ilprocess(Conv*, Ilhdr*, Block*);
static void	ilpump(Conv*);
static void	iltryclose(Conv*);
static int	ilsendctl(Conv*, int, ulong, ulong, int);
static void	ilfreeq(Ilcb*);
static void	iltryfree(Conv*);

static ulong
ilnow(void)
{
	return (ulong)osmillisec();
}

static int
illater(ulong t1, ulong t2)
{
	return (int)(t1 - t2) > 0;
}

/* Internet checksum over the IL header plus data (no pseudo header). */
static ushort
ilcsum(uchar *p, int n)
{
	ulong s;

	s = 0;
	while(n >= 2){
		s += (p[0]<<8) | p[1];
		p += 2;
		n -= 2;
	}
	if(n)
		s += p[0]<<8;
	while(s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return ~s;
}

static Block*
ilcopyb(Block *b)
{
	Block *nb;
	int n;

	n = BLEN(b);
	nb = allocb(n);
	if(n > 0)
		memmove(nb->wp, b->rp, n);
	nb->wp += n;
	return nb;
}

static void
ilsettimeout(Ilcb *ic)
{
	ulong pt;

	pt = (ic->delay>>LogAGain)
		+ ic->unackedbytes/(ic->rate>>LogAGain)
		+ (ic->mdev>>(LogDGain-1))
		+ AckDelay;
	if(pt > MaxTimeout)
		pt = MaxTimeout;
	ic->timeout = ilnow() + pt;
}

static void
ilbackoff(Ilcb *ic)
{
	ulong pt;
	int i;

	pt = (ic->delay>>LogAGain)
		+ ic->unackedbytes/(ic->rate>>LogAGain)
		+ (ic->mdev>>(LogDGain-1))
		+ AckDelay;
	for(i = 0; i < ic->rexmit; i++)
		pt = pt + (pt>>1);
	if(pt > MaxTimeout)
		pt = MaxTimeout;
	ic->timeout = ilnow() + pt;
	if(ic->fasttimeout)
		ic->timeout = ilnow()+Iltickms;
	ic->rexmit++;
}

static void
ilcbinit(Ilcb *ic)
{
	ic->start = ((ulong)osmillisec() ^ ((ulong)ic->conv->x << 12) ^ (ulong)ic) & 0xffffff;
	if(ic->start == 0)
		ic->start = 1;
	ic->next = ic->start+1;
	ic->recvd = 0;
	ic->window = Defaultwin;
	ic->cwind = Initialwin;
	ic->ssthresh = Defaultwin;
	ic->acks = 0;
	ic->inrecovery = 0;
	ic->recovery = 0;
	ic->flight = 0;
	ic->pending = nil;
	ic->outq = nil;
	ic->outqtail = nil;
	ic->outqbytes = 0;
	ic->unackedbytes = 0;
	ic->txbytes = 0;
	ic->rxqueued = 0;
	ic->peerread = 0;
	ic->creditread = 0;
	ic->flowpeer = 0;
	ic->unacked = nil;
	ic->unackedtail = nil;
	ic->outoforder = nil;
	ic->rexmit = 0;
	ic->rxtot = 0;
	ic->rxquery = 0;
	ic->qtx = 1;
	ic->fasttimeout = 0;
	ic->err[0] = 0;

	ic->delay = DefRtt<<LogAGain;
	ic->mdev = DefRtt<<LogDGain;
	ic->rate = DefByteRate<<LogAGain;
	ic->querytime = ilnow() + QueryTime;
	ic->lastrecv = ilnow();
	ilsettimeout(ic);
}

static Ilcb*
ilcbnew(Conv *c)
{
	Ilcb *ic;

	ic = malloc(sizeof(Ilcb));
	if(ic == nil)
		error(Enomem);
	memset(ic, 0, sizeof(Ilcb));
	ic->conv = c;
	ic->state = Ilclosed;
	ic->convref = 1;
	ic->rq = qopen(IlMaxrq, 0, 0, nil);
	if(ic->rq == nil){
		free(ic);
		error(Enomem);
	}
	return ic;
}

static void
ilfreeq(Ilcb *ic)
{
	qlock(&ic->ackq);
	freeblist(ic->unacked);
	ic->unacked = nil;
	ic->unackedtail = nil;
	ic->unackedbytes = 0;
	ic->flight = 0;
	qunlock(&ic->ackq);
	freeblist(ic->pending);
	ic->pending = nil;
	freeblist(ic->outq);
	ic->outq = nil;
	ic->outqtail = nil;
	ic->outqbytes = 0;
	qlock(&ic->outo);
	freeblist(ic->outoforder);
	ic->outoforder = nil;
	qunlock(&ic->outo);
}

/*
 * Release the control block once the conversation has let go of it,
 * no waiter is using it, and the connection is fully closed.
 * Called with c->l held.
 */
static void
iltryfree(Conv *c)
{
	Ilcb *ic;

	ic = (Ilcb*)c->ptcl;
	if(ic == nil || ic->convref || ic->waiters > 0 || ic->state != Ilclosed)
		return;
	c->ptcl = nil;
	c->inuse = 0;
	ilfreeq(ic);
	if(ic->rq != nil){
		qflush(ic->rq);
		qfree(ic->rq);
	}
	free(ic);
}

static int
ilnextqt(Ilcb *ic)
{
	int x;

	qlock(&ic->ackq);
	x = ic->qtx;
	if(++x > Nqt)
		x = 1;
	ic->qtx = x;
	ic->qt[x] = ic->next-1;	/* highest xmitted packet */
	ic->qt[0] = ic->qt[x];	/* compatibility with old implementations */
	qunlock(&ic->ackq);
	return x;
}

static void
ilrttcalc(Ilcb *ic, Block *bp)
{
	int rtt, tt, pt, delay, rate;

	rtt = (int)(ilnow() - ic->rttstart);
	delay = ic->delay;
	rate = ic->rate;

	/* Guard against zero wrap */
	if(rtt > 120000 || rtt < 0)
		return;

	/* this block had to be transmitted after the one acked so count its size */
	ic->rttlen += blocklen(bp) + IL_HDRSIZE;

	if(ic->rttlen < 256){
		/* guess fixed delay as rtt of small packets */
		delay += rtt - (delay>>LogAGain);
		if(delay < AGain)
			delay = AGain;
		ic->delay = delay;
	} else {
		/* if packet took longer than avg rtt delay, recalc rate */
		tt = rtt - (delay>>LogAGain);
		if(tt > 0){
			rate += ic->rttlen/tt - (rate>>LogAGain);
			if(rate < AGain)
				rate = AGain;
			ic->rate = rate;
		}
	}

	/* mdev */
	pt = ic->rttlen/(rate>>LogAGain) + (delay>>LogAGain);
	ic->mdev += abs(rtt-pt) - (ic->mdev>>LogDGain);

	if(rtt > ic->maxrtt)
		ic->maxrtt = rtt;
}

static void
ilrawsend(Conv *c, Block *bp)
{
	Ilpriv *priv;

	priv = (Ilpriv*)c->p->priv;
	if(priv == nil)
		return;
	if(isv4(c->raddr)){
		if(priv->fd4 >= 0)
			so_rawsend4(priv->fd4, c->raddr+12, bp->rp, BLEN(bp));
	} else
		so_rawsend(priv->fd, c->raddr, bp->rp, BLEN(bp));
	priv->outmsgs++;
}

static int
ilsendctl(Conv *c, int type, ulong id, ulong ack, int spec)
{
	Ilcb *ic;
	Ilhdr *ih;
	Block *bp;
	uchar *p;
	uvlong read;
	int clen;

	ic = (Ilcb*)c->ptcl;
	clen = ic->flowpeer && (type == Ilack || type == Ilstate) ? Ilcreditlen : 0;
	bp = allocb(IL_HDRSIZE+clen);
	bp->wp += IL_HDRSIZE+clen;
	ih = (Ilhdr*)bp->rp;
	hnputs(ih->illen, IL_HDRSIZE+clen);
	hnputs(ih->ilsrc, c->lport);
	hnputs(ih->ildst, c->rport);
	hnputl(ih->ilid, id);
	hnputl(ih->ilack, ack);
	ic->acksent = ack;
	ic->acktime = ilnow();
	ih->iltype = type;
	ih->ilspec = type == Ilsync ? Ilflow : spec;
	if(clen){
		/* Closing the queue discards unread data; it grants no new credit. */
		read = ic->state == Ildraining ? ic->creditread : ic->rxqueued - qlen(ic->rq);
		p = (uchar*)ih + IL_HDRSIZE;
		hnputl(p, read >> 32);
		hnputl(p+4, read);
		ic->creditread = read;
	}
	ih->ilsum[0] = 0;
	ih->ilsum[1] = 0;
	hnputs(ih->ilsum, ilcsum(bp->rp, BLEN(bp)));

	ilrawsend(c, bp);
	freeb(bp);
	return 0;
}

/* bp is a payload block; it is consumed. */
static void
ilxmit(Conv *c, Block *bp)
{
	Ilcb *ic;
	Ilhdr *ih;
	Block *nb, *np;
	int dlen;
	ulong id, ack;

	ic = (Ilcb*)c->ptcl;
	dlen = blocklen(bp);
	nb = allocb(IL_HDRSIZE + dlen);
	ih = (Ilhdr*)nb->wp;
	memset(ih, 0, IL_HDRSIZE);
	hnputs(ih->illen, dlen + IL_HDRSIZE);
	hnputs(ih->ilsrc, c->lport);
	hnputs(ih->ildst, c->rport);
	ih->iltype = Ildata;
	ih->ilspec = 0;
	nb->wp += IL_HDRSIZE;
	if(dlen > 0){
		memmove(nb->wp, bp->rp, dlen);
		nb->wp += dlen;
	}
	freeb(bp);

	qlock(&ic->ackq);
	id = ic->next++;
	hnputl(ih->ilid, id);
	ack = ic->recvd;
	hnputl(ih->ilack, ack);
	ic->acksent = ack;
	ic->acktime = ilnow() + AckDelay;
	hnputs(ih->ilsum, ilcsum(nb->rp, BLEN(nb)));

	/* keep a copy on the unacked queue in case this one gets lost */
	np = ilcopyb(nb);
	np->next = nil;
	if(ic->unacked)
		ic->unackedtail->next = np;
	else
		ic->unacked = np;
	ic->unackedtail = np;
	ic->unackedbytes += BLEN(nb);
	ic->flight++;
	qunlock(&ic->ackq);

	/* Start the round trip timer for this packet if the timer is free */
	if(ic->rttack == 0) {
		ic->rttack = id;
		ic->rttstart = ilnow();
		ic->rttlen = dlen + IL_HDRSIZE;
	}

	if(illater(ilnow(), ic->timeout))
		ilsettimeout(ic);
	ic->txbytes += dlen;
	ic->lastxmit = ilnow();
	ilrawsend(c, nb);
	freeb(nb);
}

/* Called with the conversation locked, from a writer or an incoming ack. */
static void
ilpump(Conv *c)
{
	Ilcb *ic;
	Block *bp;
	int n;

	ic = (Ilcb*)c->ptcl;
	if(ic->state == Ilclosed || ic->state == Illistening || ic->state == Ilclosing)
		return;

	while(ic->flight < ic->cwind){
		bp = ic->pending;
		if(bp == nil){
			bp = ic->outq;
			if(bp == nil)
				break;
			ic->outq = bp->next;
			if(ic->outq == nil)
				ic->outqtail = nil;
			bp->next = nil;
			ic->outqbytes -= blocklen(bp);
		}
		n = blocklen(bp) + IL_HDRSIZE;
		if(ic->flight != 0 && ic->unackedbytes + n > Maxflight){
			ic->pending = bp;
			break;
		}
		if(ic->flowpeer && ic->txbytes + blocklen(bp) > (uvlong)IlMaxrq + ic->peerread){
			ic->pending = bp;
			break;
		}
		ic->pending = nil;
		ilxmit(c, bp);
	}
}

static void
ilackto(Ilcb *ic, ulong ackto, Block *bp)
{
	Ilhdr *h;
	ulong id;
	int acked;

	if(ackto >= ic->next)
		return;

	if(ic->rttack == ackto)
		ilrttcalc(ic, bp);

	/* Cancel if we've passed the packet we were interested in */
	if(ic->rttack <= ackto)
		ic->rttack = 0;

	acked = 0;
	qlock(&ic->ackq);
	while(ic->unacked) {
		h = (Ilhdr*)ic->unacked->rp;
		id = nhgetl(h->ilid);
		if(ackto < id)
			break;

		bp = ic->unacked;
		ic->unacked = bp->next;
		bp->next = nil;
		ic->unackedbytes -= blocklen(bp);
		ic->flight--;
		acked++;
		freeblist(bp);
		ic->rexmit = 0;
		ilsettimeout(ic);
	}
	if(ic->unacked == nil)
		ic->unackedtail = nil;
	qunlock(&ic->ackq);
	if(acked != 0){
		if(ic->inrecovery && ackto >= ic->recovery)
			ic->inrecovery = 0;
		if(ic->cwind < ic->ssthresh)
			ic->cwind += acked;
		else {
			ic->acks += acked;
			while(ic->acks >= ic->cwind){
				ic->acks -= ic->cwind;
				ic->cwind++;
			}
		}
		if(ic->cwind > ic->window)
			ic->cwind = ic->window;
		Wakeup(&ic->wr);
		ilpump(ic->conv);
		iltryclose(ic->conv);
	}
}

static void
ilrexmit(Ilcb *ic)
{
	Ilhdr *h;
	Block *nb;
	Conv *c;
	Ilpriv *priv;

	nb = nil;
	qlock(&ic->ackq);
	if(ic->unacked)
		nb = ilcopyb(ic->unacked);
	qunlock(&ic->ackq);

	if(nb == nil)
		return;

	c = ic->conv;
	h = (Ilhdr*)nb->rp;

	h->iltype = Ildataquery;
	hnputl(h->ilack, ic->recvd);
	h->ilspec = ilnextqt(ic);
	h->ilsum[0] = 0;
	h->ilsum[1] = 0;
	hnputs(h->ilsum, ilcsum(nb->rp, BLEN(nb)));

	/* The state exchange confirmed loss; a timeout query alone does not. */
	if(!ic->inrecovery){
		ic->ssthresh = ic->cwind / 2;
		if(ic->ssthresh < 2)
			ic->ssthresh = 2;
		ic->cwind = ic->ssthresh;
		ic->acks = 0;
		ic->recovery = ic->next - 1;
		ic->inrecovery = 1;
	}
	/* Acknowledgements after a retransmission cannot give a valid RTT. */
	ic->rttack = 0;

	ilbackoff(ic);
	ilrawsend(c, nb);
	freeb(nb);

	ic->rxtot++;
	priv = (Ilpriv*)c->p->priv;
	if(priv != nil)
		priv->rexmit++;
}

static void
iloutoforder(Conv *c, Ilhdr *h, Block *bp)
{
	Ilcb *ic;
	Block *f, **l;
	ulong id, newid;

	ic = (Ilcb*)c->ptcl;
	bp->next = nil;

	id = nhgetl(h->ilid);
	/* Window checks */
	if(id <= ic->recvd || id > ic->recvd+ic->window) {
		freeblist(bp);
		return;
	}

	/* Packet is acceptable so sort onto receive queue for pullup */
	qlock(&ic->outo);
	if(ic->outoforder == nil)
		ic->outoforder = bp;
	else {
		l = &ic->outoforder;
		for(f = *l; f; f = f->next) {
			newid = nhgetl(((Ilhdr*)f->rp)->ilid);
			if(id <= newid) {
				if(id == newid) {
					qunlock(&ic->outo);
					freeblist(bp);
					return;
				}
				bp->next = f;
				*l = bp;
				qunlock(&ic->outo);
				return;
			}
			l = &f->next;
		}
		*l = bp;
	}
	qunlock(&ic->outo);
}

static void
ilpullup(Conv *c)
{
	Ilcb *ic;
	Ilhdr *oh;
	Block *bp;
	ulong oid, dlen;

	ic = (Ilcb*)c->ptcl;
	if(ic->state != Ilestablished)
		return;

	qlock(&ic->outo);
	while(ic->outoforder) {
		bp = ic->outoforder;
		oh = (Ilhdr*)bp->rp;
		oid = nhgetl(oh->ilid);
		if(oid <= ic->recvd) {
			ic->outoforder = bp->next;
			bp->next = nil;
			freeblist(bp);
			continue;
		}
		if(oid != ic->recvd+1)
			break;
		dlen = nhgets(oh->illen)-IL_HDRSIZE;
		if(qlen(ic->rq) + dlen > IlMaxrq)
			break;

		ic->recvd = oid;
		ic->outoforder = bp->next;
		bp->next = nil;
		bp = trimblock(bp, IL_HDRSIZE, dlen);

		/* qpassnolim consumes bp even if the queue is closed */
		qpassnolim(ic->rq, bp);
		ic->rxqueued += dlen;
	}
	qunlock(&ic->outo);
}

/* ACK and STATE carry read credit only after both SYNCs offered Ilflow. */
static int
ilcredit(Conv *c, Ilhdr *h)
{
	Ilcb *ic;
	uchar *p;
	uvlong read;

	ic = (Ilcb*)c->ptcl;
	if(!ic->flowpeer || nhgets(h->illen) < IL_HDRSIZE+Ilcreditlen)
		return 0;
	p = (uchar*)h + IL_HDRSIZE;
	read = ((uvlong)nhgetl(p) << 32) | nhgetl(p+4);
	if(read > ic->txbytes)
		read = ic->txbytes;
	if(read <= ic->peerread)
		return 0;
	ic->peerread = read;
	return 1;
}

static void
illocalclose(Conv *c)
{
	Ilcb *ic;

	ic = (Ilcb*)c->ptcl;
	ic->state = Ilclosed;
	c->lport = 0;
	ipmove(c->laddr, IPnoaddr);
}

/* Finish a local close after every queued datagram has been acknowledged. */
static void
iltryclose(Conv *c)
{
	Ilcb *ic;

	ic = (Ilcb*)c->ptcl;
	if(ic->state != Ildraining || ic->flight != 0 || ic->pending != nil || ic->outq != nil)
		return;
	ic->state = Ilclosing;
	ilsettimeout(ic);
	ilsendctl(c, Ilclose, ic->next, ic->recvd, 0);
	ilfreeq(ic);
}

static void
ilhangup(Conv *c, char *msg)
{
	Ilcb *ic, *lic, *t, **l;

	ic = (Ilcb*)c->ptcl;
	if(ic == nil)
		return;
	if(msg != nil && msg[0] != 0)
		kstrcpy(ic->err, msg, sizeof ic->err);
	lic = nil;
	if(ic->listener != nil)
		lic = (Ilcb*)ic->listener->ptcl;
	illocalclose(c);
	c->state = Hungup;
	if(lic != nil){
		qlock(&lic->alock);
		for(l = &lic->acceptq; *l != nil; l = &(*l)->anext){
			if(*l == ic){
				*l = ic->anext;
				ic->anext = nil;
				break;
			}
		}
		lic->accepttail = nil;
		for(t = lic->acceptq; t != nil; t = t->anext)
			lic->accepttail = t;
		qunlock(&lic->alock);
		ic->listener = nil;
	}
	qhangup(ic->rq, msg);
	ilfreeq(ic);
	Wakeup(&ic->cr);
	Wakeup(&ic->wr);
	Wakeup(&ic->ar);
	if(lic != nil)
		Wakeup(&lic->ar);
	iltryfree(c);
}

static void
ilconnready(Conv *c)
{
	Ilcb *ic, *lic;

	ic = (Ilcb*)c->ptcl;
	c->state = Connected;
	Wakeup(&ic->cr);
	if(ic->listener != nil){
		lic = (Ilcb*)ic->listener->ptcl;
		if(lic != nil && lic->state == Illistening){
			qlock(&lic->alock);
			ic->anext = nil;
			if(lic->accepttail != nil)
				lic->accepttail->anext = ic;
			else
				lic->acceptq = ic;
			lic->accepttail = ic;
			qunlock(&lic->alock);
			Wakeup(&lic->ar);
		}
	}
}

static void
ilprocess(Conv *c, Ilhdr *h, Block *bp)
{
	Ilcb *ic;
	Ilpriv *priv;
	ulong id, ack;

	id = nhgetl(h->ilid);
	ack = nhgetl(h->ilack);

	ic = (Ilcb*)c->ptcl;
	priv = (Ilpriv*)c->p->priv;

	ic->lastrecv = ilnow();
	ic->querytime = ilnow() + QueryTime;
	if(priv != nil)
		priv->inmsgs++;

	switch(ic->state) {
	default:
	case Ilclosed:
		freeblist(bp);
		break;
	case Ilsyncer:
		switch(h->iltype) {
		default:
			break;
		case Ilsync:
			if(ack != ic->start)
				ilhangup(c, "connection rejected");
			else {
				ic->flowpeer = (h->ilspec & Ilflow) != 0;
				ic->recvd = id;
				ic->rstart = id;
				ilsendctl(c, Ilack, ic->next, ic->recvd, 0);
				ic->state = Ilestablished;
				ic->fasttimeout = 0;
				ic->rexmit = 0;
				ilconnready(c);
				ilpullup(c);
			}
			break;
		case Ilclose:
			if(ack == ic->start)
				ilhangup(c, "connection rejected");
			break;
		}
		freeblist(bp);
		break;
	case Ilsyncee:
		switch(h->iltype) {
		default:
			break;
		case Ilsync:
			if(id != ic->rstart || ack != 0){
				illocalclose(c);
				ic->convref = 0;
				iltryfree(c);
			} else {
				ic->flowpeer = (h->ilspec & Ilflow) != 0;
				ic->recvd = id;
				ilsendctl(c, Ilsync, ic->start, ic->recvd, 0);
			}
			break;
		case Ilack:
			if(ack == ic->start) {
				ic->state = Ilestablished;
				ic->fasttimeout = 0;
				ic->rexmit = 0;
				ilconnready(c);
				ilpullup(c);
			}
			break;
		case Ildata:
			if(ack == ic->start) {
				ic->state = Ilestablished;
				ic->fasttimeout = 0;
				ic->rexmit = 0;
				ilconnready(c);
				goto established;
			}
			break;
		case Ilclose:
			if(ack == ic->start)
				ilhangup(c, "remote close");
			break;
		}
		freeblist(bp);
		break;
	case Ildraining:
	case Ilestablished:
	established:
		switch(h->iltype) {
		case Ilsync:
			if(id != ic->rstart)
				ilhangup(c, "remote close");
			else
				ilsendctl(c, Ilack, ic->next, ic->rstart, 0);
			freeblist(bp);
			break;
		case Ildata:
			/*
			 * avoid consuming all the mount rpc buffers in the
			 * system.  if the input queue is too long, drop this
			 * packet.
			 */
			if (qlen(ic->rq) >= IlMaxrq) {
				if(priv != nil)
					priv->dropped++;
				freeblist(bp);
				break;
			}

			ilackto(ic, ack, bp);
			iloutoforder(c, h, bp);
			ilpullup(c);
			break;
		case Ildataquery:
			ilackto(ic, ack, bp);
			iloutoforder(c, h, bp);
			ilpullup(c);
			ilsendctl(c, Ilstate, ic->next, ic->recvd, h->ilspec);
			break;
		case Ilack:
			id = ilcredit(c, h);
			ilackto(ic, ack, bp);
			if(id)
				ilpump(c);
			freeblist(bp);
			break;
		case Ilquery:
			ilackto(ic, ack, bp);
			ilsendctl(c, Ilstate, ic->next, ic->recvd, h->ilspec);
			freeblist(bp);
			break;
		case Ilstate:
			if(ack >= ic->rttack)
				ic->rttack = 0;
			id = ilcredit(c, h);
			ilackto(ic, ack, bp);
			if(id)
				ilpump(c);
			if(h->ilspec > Nqt)
				h->ilspec = 0;
			if(ic->qt[h->ilspec] > ack){
				ilrexmit(ic);
				ilsettimeout(ic);
			}
			freeblist(bp);
			break;
		case Ilclose:
			freeblist(bp);
			if(ack < ic->start || ack > ic->next)
				break;
			ic->recvd = id;
			ilsendctl(c, Ilclose, ic->next, ic->recvd, 0);
			ic->state = Ilclosing;
			ilsettimeout(ic);
			ilfreeq(ic);
			break;
		}
		break;
	case Illistening:
		freeblist(bp);
		break;
	case Ilclosing:
		switch(h->iltype) {
		case Ilclose:
			ic->recvd = id;
			ilsendctl(c, Ilclose, ic->next, ic->recvd, 0);
			if(ack == ic->next)
				ilhangup(c, nil);
			break;
		default:
			break;
		}
		freeblist(bp);
		break;
	}
}

static void
ilreject(Proto *p, uchar *src, Ilhdr *in)
{
	Ilpriv *priv;
	uchar buf[IL_HDRSIZE];

	priv = (Ilpriv*)p->priv;
	if(priv == nil)
		return;
	memset(buf, 0, sizeof(buf));
	hnputs(buf+2, IL_HDRSIZE);
	buf[4] = Ilclose;
	buf[5] = 0;
	hnputs(buf+6, nhgets(in->ildst));
	hnputs(buf+8, nhgets(in->ilsrc));
	hnputl(buf+10, nhgetl(in->ilack));
	hnputl(buf+14, nhgetl(in->ilid));
	hnputs(buf, ilcsum(buf, IL_HDRSIZE));
	if(isv4(src)){
		if(priv->fd4 >= 0)
			so_rawsend4(priv->fd4, src+12, buf, IL_HDRSIZE);
	} else
		so_rawsend(priv->fd, src, buf, IL_HDRSIZE);
	priv->outmsgs++;
}

static Conv*
ilfindconv(Proto *p, uchar *src, ushort dp, uchar *dst, ushort sp, int wild)
{
	Conv *cv;
	Ilcb *ic;
	int i;

	for(i = 0; i < p->nc; i++){
		cv = p->conv[i];
		if(cv == nil)
			continue;
		ic = (Ilcb*)cv->ptcl;
		if(ic == nil || ic->state == Illistening || ic->state == Ilclosed)
			continue;
		if(cv->lport != sp || cv->rport != dp)
			continue;
		if(ipcmp(cv->raddr, src) != 0)
			continue;
		if(ipcmp(cv->laddr, dst) == 0)
			return cv;
		if(wild && ipcmp(cv->laddr, IPnoaddr) == 0)
			return cv;
	}
	return nil;
}

static Conv*
ilfindlistener(Proto *p, uchar *dst, ushort sp, int wild)
{
	Conv *cv;
	Ilcb *ic;
	int i;

	for(i = 0; i < p->nc; i++){
		cv = p->conv[i];
		if(cv == nil)
			continue;
		ic = (Ilcb*)cv->ptcl;
		if(ic == nil || ic->state != Illistening)
			continue;
		if(cv->lport != sp)
			continue;
		if(ipcmp(cv->laddr, dst) == 0)
			return cv;
		if(wild && ipcmp(cv->laddr, IPnoaddr) == 0)
			return cv;
	}
	return nil;
}

static Conv*
ilnewcall(Proto *p, Conv *lcv, uchar *src, ushort dp, uchar *dst, ushort sp, ulong id)
{
	Conv *cv;
	Ilcb *ic;

	cv = protoclone(p, lcv->owner, -2);
	if(cv == nil)
		return nil;
	ic = ilcbnew(cv);
	cv->ptcl = ic;
	ilcbinit(ic);
	memmove(cv->raddr, src, IPaddrlen);
	cv->rport = dp;
	memmove(cv->laddr, dst, IPaddrlen);
	cv->lport = sp;
	cv->state = Connecting;
	ic->state = Ilsyncee;
	ic->rstart = id;
	ic->listener = lcv;
	return cv;
}

/*
 * The hosted raw socket delivers a copy of every packet we send.
 * Recognise those by the reverse tuple so they are not mistaken
 * for peer traffic (which would, among other things, make a SYNC
 * generate a reject that looks like a peer refusal).
 */
static int
ilselfsent(Proto *p, uchar *src, ushort dp, uchar *dst, ushort sp)
{
	Conv *cv;
	Ilcb *ic;
	int i;

	for(i = 0; i < p->nc; i++){
		cv = p->conv[i];
		if(cv == nil)
			continue;
		ic = (Ilcb*)cv->ptcl;
		if(ic == nil || ic->state == Illistening || ic->state == Ilclosed)
			continue;
		if(cv->lport != dp || cv->rport != sp)
			continue;
		if(ipcmp(cv->raddr, dst) != 0)
			continue;
		if(ipcmp(cv->laddr, src) == 0 || ipcmp(cv->laddr, IPnoaddr) == 0)
			return 1;
	}
	return 0;
}

static void
ildispatch(Proto *p, uchar *buf, int n, uchar *src, uchar *dst)
{
	Ilpriv *priv;
	Ilhdr *ih;
	Block *bp;
	Conv *cv;
	ushort sp, dp;
	int illen;

	priv = (Ilpriv*)p->priv;
	if(priv == nil || n < IL_HDRSIZE)
		return;
	ih = (Ilhdr*)buf;
	illen = nhgets(ih->illen);
	if(illen < IL_HDRSIZE || illen > n)
		return;
	if(ilcsum(buf, illen) != 0){
		priv->csumerrs++;
		return;
	}
	if(ih->iltype > Ilclose)
		return;
	sp = nhgets(ih->ildst);	/* local port */
	dp = nhgets(ih->ilsrc);	/* remote port */

	bp = allocb(illen);
	memmove(bp->wp, buf, illen);
	bp->wp += illen;
	ih = (Ilhdr*)bp->rp;

	cv = ilfindconv(p, src, dp, dst, sp, 0);
	if(cv == nil)
		cv = ilfindconv(p, src, dp, dst, sp, 1);
	if(cv == nil && ih->iltype == Ilsync){
		cv = ilfindlistener(p, dst, sp, 0);
		if(cv == nil)
			cv = ilfindlistener(p, dst, sp, 1);
		if(cv != nil){
			if(waserror()){
				freeblist(bp);
				return;
			}
			cv = ilnewcall(p, cv, src, dp, dst, sp, nhgetl(ih->ilid));
			poperror();
		}
	}
	if(cv == nil && ilselfsent(p, src, dp, dst, sp)){
		freeblist(bp);
		return;
	}
	if(cv == nil){
		if(ih->iltype != Ilclose && ilrejectenabled)
			ilreject(p, src, ih);
		freeblist(bp);
		return;
	}

	qlock(&cv->l);
	if(waserror()){
		qunlock(&cv->l);
		freeblist(bp);
		return;
	}
	ilprocess(cv, ih, bp);
	qunlock(&cv->l);
	poperror();
}

static void
ilrxloop(Proto *p, int v4)
{
	Ilpriv *priv;
	uchar *buf, src[IPaddrlen], dst[IPaddrlen];
	int n;

	priv = (Ilpriv*)p->priv;
	buf = malloc(65536);
	if(buf == nil)
		pexit("ilrx: no memory", 1);
	for(;;){
		if(v4)
			n = so_rawrecv4(priv->fd4, buf, 65536, src, dst);
		else
			n = so_rawrecv(priv->fd, buf, 65536, src, dst);
		if(n < 0){
			osmillisleep(20);
			continue;
		}
		/* the host delivers raw packets starting at the IL header */
		ildispatch(p, buf, n, src, dst);
	}
}

static void
ilrxproc(void *a)
{
	ilrxloop((Proto*)a, 0);
}

static void
ilrx4proc(void *a)
{
	ilrxloop((Proto*)a, 1);
}

static void
iltick(Conv *c, Ilcb *ic)
{
	switch(ic->state) {
	case Ilclosed:
	case Illistening:
		break;
	case Ilclosing:
		if(illater(ilnow(), ic->timeout)) {
			if(ic->rexmit > MaxRexmit){
				ilhangup(c, nil);
				break;
			}
			ilsendctl(c, Ilclose, ic->next, ic->recvd, 0);
			ilbackoff(ic);
		}
		break;

	case Ilsyncee:
	case Ilsyncer:
		if(illater(ilnow(), ic->timeout)) {
			if(ic->rexmit > MaxRexmit){
				ilhangup(c, "connection timed out");
				break;
			}
			ilsendctl(c, Ilsync, ic->start, ic->recvd, 0);
			ilbackoff(ic);
		}
		break;

	case Ildraining:
	case Ilestablished:
		if(ic->outoforder != nil)
			ilpullup(c);
		if(ic->recvd != ic->acksent)
		if(illater(ilnow(), ic->acktime))
			ilsendctl(c, Ilack, ic->next, ic->recvd, 0);
		if(ic->state == Ilestablished && ic->flowpeer && ic->rxqueued - qlen(ic->rq) > ic->creditread)
			ilsendctl(c, Ilack, ic->next, ic->recvd, 0);

		if(illater(ilnow(), ic->querytime)){
			if(illater(ilnow(), ic->lastrecv+DeathTime)){
				ilhangup(c, "connection timed out");
				break;
			}
			ilsendctl(c, Ilquery, ic->next, ic->recvd, ilnextqt(ic));
			ic->querytime = ilnow() + QueryTime;
		}

		if(ic->unacked != nil)
		if(illater(ilnow(), ic->timeout)) {
			if(ic->rexmit > MaxRexmit){
				ilhangup(c, "connection timed out");
				break;
			}
			ilsendctl(c, Ilquery, ic->next, ic->recvd, ilnextqt(ic));
			ic->rxquery++;
			ilbackoff(ic);
		}
		break;
	}
}

static void
iltimeproc(void *a)
{
	Proto *p;
	Conv *cv, **list;
	Ilcb *ic;
	int i, n;

	p = (Proto*)a;
	for(;;){
		osmillisleep(Iltickms);
		qlock(&p->l);
		n = p->nc;
		list = malloc(sizeof(Conv*) * (n > 0 ? n : 1));
		if(list == nil){
			qunlock(&p->l);
			continue;
		}
		for(i = 0; i < n; i++)
			list[i] = p->conv[i];
		qunlock(&p->l);
		for(i = 0; i < n; i++){
			cv = list[i];
			if(cv == nil || cv->ptcl == nil)
				continue;
			qlock(&cv->l);
			if(waserror()){
				qunlock(&cv->l);
				continue;
			}
			ic = (Ilcb*)cv->ptcl;
			if(ic != nil)
				iltick(cv, ic);
			qunlock(&cv->l);
			poperror();
		}
		free(list);
	}
}

static Ilpriv*
ilensure(Proto *p)
{
	Ilpriv *priv;

	priv = (Ilpriv*)p->priv;
	if(priv != nil && priv->started)
		return priv;
	if(priv == nil){
		priv = malloc(sizeof(Ilpriv));
		if(priv == nil)
			error(Enomem);
		memset(priv, 0, sizeof(Ilpriv));
		p->priv = priv;
	}
	qlock(&priv->l);
	if(waserror()){
		qunlock(&priv->l);
		nexterror();
	}
	if(!priv->started){
		priv->fd = so_rawil();
		priv->fd4 = -1;
		if(!waserror()){
			priv->fd4 = so_rawil4();
			poperror();
		}
		priv->started = 1;
		kproc("ilrx", ilrxproc, p, 0);
		if(priv->fd4 >= 0)
			kproc("ilrx4", ilrx4proc, p, 0);
		kproc("iltime", iltimeproc, p, 0);
	}
	poperror();
	qunlock(&priv->l);
	return priv;
}

static ushort
ilallocport(Proto *p, Conv *self)
{
	Conv *cv;
	int i, j, used;
	ushort cand;

	for(j = 0; j < 20000; j++){
		cand = 30000 + ((ilnow() + j) % 20000);
		used = 0;
		for(i = 0; i < p->nc; i++){
			cv = p->conv[i];
			if(cv == nil || cv == self)
				continue;
			if(cv->ptcl != nil && cv->lport == cand){
				used = 1;
				break;
			}
		}
		if(!used)
			return cand;
	}
	error("no free il port");
	return 0;
}

/*
 * Parse an announce/bind argument of the form [address!]port,
 * where address may be "*" and port may be "*".
 * No socket is touched: IL ports live in the IL header.
 */
static void
ilsetladdrport(Conv *c, char *str)
{
	char *p;

	p = strchr(str, '!');
	if(p == nil){
		ipmove(c->laddr, IPnoaddr);
		if(strcmp(str, "*") == 0)
			c->lport = 0;
		else
			c->lport = portno(str);
		return;
	}
	*p++ = 0;
	if(strcmp(str, "*") == 0)
		ipmove(c->laddr, IPnoaddr);
	else if(parseip(c->laddr, str) == 0)
		error("invalid IP address");
	if(strcmp(p, "*") == 0)
		c->lport = 0;
	else
		c->lport = portno(p);
}

/* Learn the local address the host would use toward the peer. */
static void
illearnladdr(Conv *c)
{
	int fd;
	uchar addr[IPaddrlen];
	ushort port;

	if(waserror())
		return;
	fd = so_socket(S_UDP);
	so_connect(fd, c->raddr, c->rport != 0 ? c->rport : 9);
	so_getsockname(fd, addr, &port);
	so_close(fd);
	ipmove(c->laddr, addr);
	poperror();
}

static void
ilstatus(Conv *c, char *buf, int n)
{
	Ilcb *ic;

	ic = (Ilcb*)c->ptcl;
	if(ic == nil){
		snprint(buf, n, "%s il Closed\n", ipstates[c->state]);
		return;
	}
	snprint(buf, n, "%s il %s qin %d qout %lud una %lud cwnd %d flight %d rex %d\n",
		ipstates[c->state], ilstates[ic->state],
		ic->rq ? qlen(ic->rq) : 0, ic->outqbytes, ic->unackedbytes,
		ic->cwind, ic->flight, ic->rxtot);
}

static long
ilreadq(Conv *c, void *a, long n)
{
	Ilcb *ic;

	ic = (Ilcb*)c->ptcl;
	if(ic == nil || ic->state == Illistening)
		error(Ehungup);
	return qread(ic->rq, a, n);
}

static int
ilwspace(void *v)
{
	Conv *c;
	Ilcb *ic;

	c = (Conv*)v;
	ic = (Ilcb*)c->ptcl;
	if(ic == nil || ic->state != Ilestablished)
		return 1;
	return ic->unackedbytes + ic->outqbytes <= IlMaxrq;
}

static long
ilwriteq(Conv *c, void *a, long n)
{
	Ilcb *ic;
	Block *bp;

	ic = (Ilcb*)c->ptcl;
	if(ic == nil)
		error(Ehungup);
	if(n > Ilmaxmsg)
		error("il message too large");
	qlock(&c->wlock);
	if(waserror()){
		qunlock(&c->wlock);
		nexterror();
	}
	for(;;){
		qlock(&c->l);
		if(ic->state != Ilestablished){
			qunlock(&c->l);
			if(ic->err[0])
				error(ic->err);
			error(Ehungup);
		}
		if(ic->unackedbytes + ic->outqbytes <= IlMaxrq){
			bp = allocb(n);
			if(n > 0){
				memmove(bp->wp, a, n);
				bp->wp += n;
			}
			bp->next = nil;
			if(ic->outqtail != nil)
				ic->outqtail->next = bp;
			else
				ic->outq = bp;
			ic->outqtail = bp;
			ic->outqbytes += n;
			ilpump(c);
			qunlock(&c->l);
			break;
		}
		qunlock(&c->l);
		Sleep(&ic->wr, ilwspace, c);
	}
	poperror();
	qunlock(&c->wlock);
	return n;
}

static int
ilacccan(void *v)
{
	Conv *c;
	Ilcb *ic;

	c = (Conv*)v;
	ic = (Ilcb*)c->ptcl;
	if(ic == nil || ic->state == Ilclosed)
		return 1;
	return ic->acceptq != nil;
}

static Conv*
ilaccept(Conv *lcv)
{
	Ilcb *ic, *nc;

	ic = (Ilcb*)lcv->ptcl;
	if(ic == nil || ic->state != Illistening)
		error("not announced");
	Sleep(&ic->ar, ilacccan, lcv);
	qlock(&ic->alock);
	nc = ic->acceptq;
	if(nc != nil){
		ic->acceptq = nc->anext;
		if(ic->acceptq == nil)
			ic->accepttail = nil;
		nc->anext = nil;
		nc->listener = nil;
	}
	qunlock(&ic->alock);
	if(nc == nil)
		error(Ehungup);
	return nc->conv;
}

static void
ilstart(Conv *c, int state)
{
	Ilcb *ic;

	ic = (Ilcb*)c->ptcl;
	ilcbinit(ic);
	ic->state = state;
	if(state == Ilsyncer)
		ilsendctl(c, Ilsync, ic->start, ic->recvd, 0);
}

static int
ilconned(void *v)
{
	Conv *c;
	Ilcb *ic;

	c = (Conv*)v;
	ic = (Ilcb*)c->ptcl;
	if(ic == nil)
		return 1;
	return ic->state == Ilestablished || ic->state == Ilclosed;
}

static void
ilctlmsg(Proto *p, Conv *c, Cmdbuf *cb)
{
	Ilcb *ic;
	char *e;

	if(strcmp(cb->f[0], "connect") == 0){
		if(c->state != Idle)
			error(Econinuse);
		c->cerr[0] = 0;
		if(cb->nf < 2 || cb->nf > 3)
			error("bad args to connect");
		e = setraddrport(c, cb->f[1]);
		if(e != nil)
			error(e);
		if(cb->nf == 3)
			c->lport = portno(cb->f[2]);
		ilensure(p);
		ic = ilcbnew(c);
		c->ptcl = ic;
		if(c->lport == 0)
			c->lport = ilallocport(p, c);
		if(ipcmp(c->laddr, IPnoaddr) == 0)
			illearnladdr(c);
		c->state = Connecting;
		ilstart(c, Ilsyncer);
		ic->waiters++;
		if(waserror()){
			qlock(&c->l);
			ic->waiters--;
			nexterror();
		}
		qunlock(&c->l);
		Sleep(&ic->cr, ilconned, c);
		qlock(&c->l);
		poperror();
		ic->waiters--;
		if(ic->state != Ilestablished){
			if(ic->err[0])
				error(ic->err);
			error("connection timed out");
		}
	} else if(strcmp(cb->f[0], "announce") == 0){
		if(c->state != Idle)
			error(Econinuse);
		if(cb->nf != 2)
			error("bad args to announce");
		ilensure(p);
		ilsetladdrport(c, cb->f[1]);
		ic = ilcbnew(c);
		c->ptcl = ic;
		ilcbinit(ic);
		if(c->lport == 0)
			c->lport = ilallocport(p, c);
		ic->state = Illistening;
		ipmove(c->raddr, IPnoaddr);
		c->rport = 0;
		c->state = Announced;
	} else if(strcmp(cb->f[0], "bind") == 0){
		if(cb->nf != 2)
			error("bad args to bind");
		ilsetladdrport(c, cb->f[1]);
	} else if(strcmp(cb->f[0], "hangup") == 0){
		ic = (Ilcb*)c->ptcl;
		if(ic != nil){
			if(ic->state == Ilestablished){
				ic->state = Ildraining;
				ilpump(c);
				iltryclose(c);
			} else if(ic->state == Ilsyncer || ic->state == Ilsyncee)
				ilhangup(c, nil);
		}
	} else if(strcmp(cb->f[0], "ttl") == 0 || strcmp(cb->f[0], "tos") == 0
		|| strcmp(cb->f[0], "ignoreadvice") == 0 || strcmp(cb->f[0], "keepalive") == 0){
		/* ignored, as for the hosted protocols */
	} else
		error(Enoctl);
}

static void
ilcloseconv(Conv *c)
{
	Ilcb *ic;

	ic = (Ilcb*)c->ptcl;
	if(ic == nil)
		return;
	ic->convref = 0;
	switch(ic->state){
	case Illistening:
		ic->state = Ilclosed;
		Wakeup(&ic->ar);
		break;
	case Ilestablished:
		ic->state = Ildraining;
		ilpump(c);
		iltryclose(c);
		break;
	case Ilsyncer:
	case Ilsyncee:
		ilhangup(c, nil);
		break;
	case Ilclosing:
	case Ildraining:
	case Ilclosed:
		break;
	}
	iltryfree(c);
}

Dev ipdevtab = {
	'I',
	"ip",

	ipinit,
	ipattach,
	ipwalk,
	ipstat,
	ipopen,
	devcreate,
	ipclose,
	ipread,
	devbread,
	ipwrite,
	devbwrite,
	devremove,
	ipwstat
};

int
Fsproto(Fs *f, Proto *p)
{
	if(f->np >= Maxproto)
		return -1;

	p->f = f;

	if(p->ipproto > 0){
		if(f->t2p[p->ipproto] != nil)
			return -1;
		f->t2p[p->ipproto] = p;
	}

	p->qid.type = QTDIR;
	p->qid.path = QID(f->np, 0, Qprotodir);
	p->conv = malloc(sizeof(Conv*)*(p->nc+1));
	if(p->conv == nil)
		panic("Fsproto");

	p->x = f->np;
	f->p[f->np++] = p;

	return 0;
}

/*
 *  return true if this protocol is
 *  built in
 */
int
Fsbuiltinproto(Fs* f, uchar proto)
{
	return f->t2p[proto] != nil;
}
