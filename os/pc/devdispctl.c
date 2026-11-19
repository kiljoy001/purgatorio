#include	"u.h"
#include	"../port/lib.h"
#include	"mem.h"
#include	"dat.h"
#include	"fns.h"
#include	"../port/error.h"

/*
 *  Display control: the scale factor the 9vm viewer applies to the
 *  1024x768 guest frame.  The value is a percentage (100 = 1:1) and is
 *  also published in the shared vmdisplay header, so a viewer that maps
 *  it can pick the change up without another channel.
 */

enum
{
	Qdir = 0,
	Qscale,
};

static Dirtab dispctldir[] =
{
	".",	{Qdir, 0, QTDIR},	0,	DMDIR|0555,
	"scale",	{Qscale, 0, QTFILE},	0,	0666,
};

extern int	vmdispgetscale(void);
extern int	vmdispsetscale(int);

static Chan*
dispctlattach(char *spec)
{
	return devattach('g', spec);
}

static Walkqid*
dispctlwalk(Chan *c, Chan *nc, char **name, int nname)
{
	return devwalk(c, nc, name, nname, dispctldir, nelem(dispctldir), devgen);
}

static int
dispctlstat(Chan *c, uchar *dp, int n)
{
	return devstat(c, dp, n, dispctldir, nelem(dispctldir), devgen);
}

static Chan*
dispctlopen(Chan *c, int omode)
{
	return devopen(c, omode, dispctldir, nelem(dispctldir), devgen);
}

static void
dispctlclose(Chan *c)
{
	USED(c);
}

static long
dispctlread(Chan *c, void *buf, long n, vlong off)
{
	char s[32];

	if(c->qid.type & QTDIR)
		return devdirread(c, buf, n, dispctldir, nelem(dispctldir), devgen);
	if(c->qid.path != Qscale)
		error(Egreg);
	snprint(s, sizeof s, "%d\n", vmdispgetscale());
	return readstr(off, buf, n, s);
}

static long
dispctlwrite(Chan *c, void *buf, long n, vlong off)
{
	char s[32], *f[2];
	int v;

	USED(off);
	if(c->qid.path != Qscale)
		error(Egreg);
	if(n <= 0 || n >= sizeof s)
		error(Ebadarg);
	memmove(s, buf, n);
	s[n] = 0;
	if(tokenize(s, f, 2) != 2 || strcmp(f[0], "scale") != 0)
		error(Ebadarg);
	v = atoi(f[1]);
	if(vmdispsetscale(v) < 0)
		error(Ebadarg);
	return n;
}

Dev dispctldevtab =
{
	'g',
	"dispctl",

	devreset,
	devinit,
	devshutdown,
	dispctlattach,
	dispctlwalk,
	dispctlstat,
	dispctlopen,
	devcreate,
	dispctlclose,
	dispctlread,
	devbread,
	dispctlwrite,
	devbwrite,
	devremove,
	devwstat,
};
