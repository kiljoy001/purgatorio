#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "io.h"
#include "../port/error.h"
#include "../port/sd.h"

/*
 * Virtio block device over the 9vm hypervisor's simplified Virtio 1.0
 * MMIO transport.  One queue, no feature negotiation, and synchronous
 * I/O: the hypervisor completes a kicked request before the notify
 * write returns, so nothing here waits or polls.
 */

enum {
	QSZ		= 16,		/* matches 9vm's queue size */

	/* simplified virtio MMIO registers (byte offsets) */
	VDevFeatSel	= 0x000,
	VDevFeat	= 0x004,
	VNumQueues	= 0x012,
	VDevStatus	= 0x014,
	VQueueSel	= 0x016,
	VQueueSize	= 0x018,
	VQueueReady	= 0x01C,
	VQueueDesc	= 0x020,
	VQueueAvail	= 0x028,
	VQueueUsed	= 0x030,
	VQueueNotify	= 0x100,
	VISR		= 0x200,
	VDevConfig	= 0x300,

	/* device status */
	VSAck		= 1,
	VSDriver	= 2,
	VSDriverOk	= 4,

	/* virtio-blk request types */
	VBlkIn		= 0,		/* read */
	VBlkOut		= 1,		/* write */

	/* descriptor flags */
	VDescNext	= 1,
	VDescWrite	= 2,
};

typedef struct Vring Vring;
struct Vring {
	struct {
		uvlong	addr;
		ulong	len;
		ushort	flags;
		ushort	next;
	} desc[QSZ];
	struct {
		ushort	flags;
		ushort	idx;
		ushort	ring[QSZ];
	} avail;
	struct {
		ushort	flags;
		ushort	idx;
		struct {
			ulong	id;
			ulong	len;
		} ring[QSZ];
	} used;
};

typedef struct Vbdev Vbdev;
struct Vbdev {
	ulong	pa;		/* BAR0 physical address */
	uchar*	mmio;		/* BAR0 kernel virtual address */
	Vring*	ring;
	QLock;
	ulong	capacity;	/* 512-byte sectors */
	uvlong	reqhdr[2];	/* 16-byte request header */
	uchar	reqstatus;
};

SDifc sdvirtioifc;

static ulong
vbr32(Vbdev *vb, int off)
{
	return *(volatile ulong*)(vb->mmio + off);
}

static void
vbw32(Vbdev *vb, int off, ulong v)
{
	*(volatile ulong*)(vb->mmio + off) = v;
}

static ushort
vbr16(Vbdev *vb, int off)
{
	return *(volatile ushort*)(vb->mmio + off);
}

static void
vbw16(Vbdev *vb, int off, ushort v)
{
	*(volatile ushort*)(vb->mmio + off) = v;
}

static void
vbw8(Vbdev *vb, int off, uchar v)
{
	*(volatile uchar*)(vb->mmio + off) = v;
}

static long
sdvirtiobio(SDunit *unit, int, int write, void *data, long nb, long bno)
{
	Vbdev *vb;
	Vring *r;
	uchar *hdr;

	vb = unit->dev->ctlr;
	r = vb->ring;

	qlock(vb);

	hdr = (uchar*)vb->reqhdr;
	*(ulong*)(hdr + 0) = write ? VBlkOut : VBlkIn;
	*(ulong*)(hdr + 4) = 0;
	*(uvlong*)(hdr + 8) = (uvlong)bno;

	/* descriptor 0: request header (device reads) */
	r->desc[0].addr = (uvlong)PADDR(hdr);
	r->desc[0].len = 16;
	r->desc[0].flags = VDescNext;
	r->desc[0].next = 1;

	/* descriptor 1: data (device writes on read, reads on write) */
	r->desc[1].addr = (uvlong)PADDR(data);
	r->desc[1].len = nb * unit->secsize;
	r->desc[1].flags = (write ? 0 : VDescWrite) | VDescNext;
	r->desc[1].next = 2;

	/* descriptor 2: status byte (device writes) */
	r->desc[2].addr = (uvlong)PADDR(&vb->reqstatus);
	r->desc[2].len = 1;
	r->desc[2].flags = VDescWrite;
	r->desc[2].next = 0;

	/* publish the head and kick; the hypervisor completes inline */
	vb->reqstatus = 0xFF;
	r->avail.ring[r->avail.idx % QSZ] = 0;
	r->avail.idx++;
	vbw16(vb, VQueueNotify, 0);

	if(vb->reqstatus != 0){
		qunlock(vb);
		error(Eio);
	}
	qunlock(vb);
	return nb * unit->secsize;
}

static int
sdvirtioenable(SDev *sdev)
{
	Vbdev *vb;

	vb = sdev->ctlr;
	if(vb->mmio != nil)
		return 1;

	if(mmukmap(vb->pa, 0, 4096) == 0)
		return 0;
	vb->mmio = (uchar*)KADDR(vb->pa);

	/* reset */
	vbw8(vb, VDevStatus, 0);

	vb->ring = xalloc(sizeof(Vring));
	if(vb->ring == nil)
		return 0;
	memset(vb->ring, 0, sizeof(Vring));

	/* no feature negotiation */
	vbw32(vb, VDevFeatSel, 0);
	vbw8(vb, VDevStatus, VSAck | VSDriver);

	/* set up queue 0 */
	vbw16(vb, VQueueSel, 0);
	vbw32(vb, VQueueDesc, PADDR(&vb->ring->desc[0]));
	vbw32(vb, VQueueAvail, PADDR(&vb->ring->avail));
	vbw32(vb, VQueueUsed, PADDR(&vb->ring->used));
	vbw16(vb, VQueueReady, 1);

	vbw8(vb, VDevStatus, VSAck | VSDriver | VSDriverOk);

	/* capacity in 512-byte sectors */
	vb->capacity = vbr32(vb, VDevConfig);
	vb->capacity |= (uvlong)vbr32(vb, VDevConfig + 4) << 32;

	return 1;
}

static int
sdvirtioverify(SDunit *unit)
{
	Vbdev *vb;

	vb = unit->dev->ctlr;
	if(vb->capacity == 0)
		return 0;
	memset(unit->inquiry, 0, sizeof(unit->inquiry));
	unit->inquiry[0] = 0x00;	/* direct-access device */
	unit->sectors = 0;		/* force sdinitpart to re-read geometry */
	unit->secsize = 0;
	return 1;
}

static int
sdvirtioonline(SDunit *unit)
{
	Vbdev *vb;

	vb = unit->dev->ctlr;
	if(vb->capacity == 0)
		return 0;
	unit->sectors = vb->capacity;
	unit->secsize = 512;
	return 0;
}

static SDev*
sdvirtiopnp(void)
{
	Pcidev *p;
	Vbdev *vb;
	SDev *sdev;

	p = nil;
	while((p = pcimatch(p, 0x1AF4, 0x1001)) != nil){
		vb = malloc(sizeof(Vbdev));
		if(vb == nil)
			break;
		memset(vb, 0, sizeof(*vb));
		vb->pa = p->mem[0].bar;

		sdev = malloc(sizeof(SDev));
		if(sdev == nil){
			free(vb);
			break;
		}
		memset(sdev, 0, sizeof(*sdev));
		sdev->ifc = &sdvirtioifc;
		sdev->ctlr = vb;
		sdev->nunit = 1;
		return sdev;
	}
	return nil;
}

static SDev*
sdvirioid(SDev *sdev)
{
	char name[32];
	static char idno[16] = "0123456789abcdef";
	static char *p = idno;

	while(sdev != nil){
		if(sdev->ifc == &sdvirtioifc){
			sdev->idno = *p++;
			snprint(name, sizeof(name), "sd%c", sdev->idno);
			kstrdup(&sdev->name, name);
			if(p >= &idno[sizeof(idno)])
				break;
		}
		sdev = sdev->next;
	}
	return nil;
}

SDifc sdvirtioifc = {
	"virtio",		/* name */

	sdvirtiopnp,		/* pnp */
	nil,			/* legacy */
	sdvirioid,		/* id */
	sdvirtioenable,		/* enable */
	nil,			/* disable */

	sdvirtioverify,		/* verify */
	sdvirtioonline,		/* online */
	nil,			/* rio */
	nil,			/* rctl */
	nil,			/* wctl */

	sdvirtiobio,		/* bio */
	nil,			/* probe */
	nil,			/* clear */
	nil,			/* stat */
};
