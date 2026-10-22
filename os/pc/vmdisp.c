#include "u.h"
#include "../port/lib.h"
#include "mem.h"
#include "dat.h"
#include "fns.h"
#include "io.h"
#include "../port/error.h"

#include <draw.h>
#include <memdraw.h>
#include "screen.h"

/*
 * 9vm display.
 *
 * When 9vm is started with -display-shm it maps its display shared memory
 * into the guest at a fixed physical address.  The layout is the host
 * struct vmdisplay: two 1024x768 XRGB32 slots, a begin/commit state machine
 * and a ring of text input events.  We draw into a normal kernel shadow
 * framebuffer and copy the changed rectangle into a free slot on flush.
 */

enum {
	Vmdmagic	= 0x56444c39,
	Vmdwidth	= 1024,
	Vmdheight	= 768,
	Vmdslots	= 2,
	Vmdevents	= 256,
	Vmdeventbytes	= 96,
	Vmdframebytes	= Vmdwidth*Vmdheight*4,

	/* keep clear of the IOAPIC (0xFEC00000) and LAPIC (0xFEE00000) */
	Vmdguestaddr	= 0xF8000000,

	VmdFree		= 0,
	VmdWriting	= 1,
	VmdReady	= 2,
	VmdReading	= 3,
	VmdDeltaWrites	= 0x80000000,
};

typedef struct Vmdisplay Vmdisplay;
struct Vmdisplay {
	uint	magic;
	uint	version;
	uint	width;
	uint	height;
	uvlong	latest_serial;
	uint	latest_slot;
	uint	state[Vmdslots];
	uint	written[Vmdslots];
	uint	_pad0;			/* keep slot_serial 8-byte aligned as on the host */
	uvlong	slot_serial[Vmdslots];
	uint	input_head;
	uint	input_tail;
	char	input[Vmdevents][Vmdeventbytes];
	uint	pixels[Vmdslots][Vmdwidth*Vmdheight];
};

static Vmdisplay *vmdisp;
static uint vmdispserial;
static int vmdispnextslot;
static int vmdispbuttons;

static void
vmdispflush(VGAscr *scr, Rectangle r)
{
	int slot;
	uchar *src;

	if(vmdisp == nil || scr == nil || scr->gscreen == nil || scr->gscreendata == nil)
		return;
	if(rectclip(&r, scr->gscreen->r) == 0)
		return;

	/*
	 * Present whole frames into alternating slots.  Copying the full
	 * shadow keeps each slot self-contained, so a slot is always a valid
	 * frame even if the host viewer has not consumed the other one.
	 */
	slot = vmdispnextslot;
	if(vmdisp->state[slot] != VmdFree && vmdisp->state[1-slot] == VmdFree)
		slot = 1-slot;

	src = scr->gscreendata->bdata;
	memmove(vmdisp->pixels[slot], src, Vmdframebytes);

	vmdisp->written[slot] = Vmdframebytes;
	vmdisp->slot_serial[slot] = ++vmdispserial;
	vmdisp->state[slot] = VmdReady;
	vmdisp->latest_slot = slot;
	vmdisp->latest_serial = vmdispserial;
	vmdispnextslot = 1-slot;
}

static void
vmdispenable(VGAscr*)
{
}

VGAdev vmdispdev = {
	"vmdisp",

	vmdispenable,
	nil,
	nil,
	nil,
	nil,
	nil,
	nil,
	nil,
	vmdispflush,
};

static void
vmdispkey(int sym, int mod)
{
	int c;

	if(mod & 2){			/* ctrl */
		if(sym >= 'a' && sym <= 'z')
			sym = sym - 'a' + 1;
		else if(sym >= 'A' && sym <= 'Z')
			sym = sym - 'A' + 1;
	}
	switch(sym){
	case 13:
		c = '\n';
		break;
	case 8:
		c = 0x08;
		break;
	case 9:
		c = '\t';
		break;
	case 27:
		c = 0x1b;
		break;
	case 127:
		c = 0x7f;
		break;
	default:
		if(sym < 0x20 || sym > 0x10FFFF)
			return;
		c = sym;
		break;
	}
	if(mod & 1)			/* alt/meta */
		kbdputc(kbdq, 0x1b);
	kbdputc(kbdq, c);
}

static void
vmdispevent(char *e)
{
	int x, y, sym, mod;
	char *p;

	if(strncmp(e, "down ", 5) == 0){
		x = strtoul(e+5, &p, 10);
		y = strtoul(p, nil, 10);
		vmdispbuttons = 1;
		mousetrack(1, x, y, 0);
	}else if(strncmp(e, "up ", 3) == 0){
		x = strtoul(e+3, &p, 10);
		y = strtoul(p, nil, 10);
		vmdispbuttons = 0;
		mousetrack(0, x, y, 0);
	}else if(strncmp(e, "move ", 5) == 0){
		x = strtoul(e+5, &p, 10);
		y = strtoul(p, nil, 10);
		mousetrack(vmdispbuttons, x, y, 0);
	}else if(strncmp(e, "key ", 4) == 0){
		sym = strtoul(e+4, &p, 10);
		mod = strtoul(p, nil, 10);
		vmdispkey(sym, mod);
	}
}

static void
vmdispinput(void*)
{
	char *e;

	for(;;){
		while(vmdisp != nil && vmdisp->input_tail != vmdisp->input_head){
			e = vmdisp->input[vmdisp->input_tail % Vmdevents];
			e[Vmdeventbytes-1] = 0;
			vmdispevent(e);
			vmdisp->input_tail++;
		}
		tsleep(&up->sleep, return0, nil, 20);
	}
}

void
vmdispinit(void)
{
	VGAscr *scr;

	if(mmukmap(Vmdguestaddr, 0, sizeof(Vmdisplay)) == 0)
		return;
	vmdisp = (Vmdisplay*)KADDR(Vmdguestaddr);
	if(vmdisp->magic != Vmdmagic ||
	   vmdisp->width != Vmdwidth || vmdisp->height != Vmdheight){
		vmdisp = nil;
		return;
	}

	vmdispnextslot = 0;
	vmdisp->state[0] = VmdFree;
	vmdisp->state[1] = VmdFree;

	scr = &vgascreen[0];
	scr->dev = &vmdispdev;
	if(waserror()){
		poperror();
		vmdisp = nil;
		return;
	}
	if(screensize(Vmdwidth, Vmdheight, 32, XRGB32) != 0){
		poperror();
		vmdisp = nil;
		return;
	}
	poperror();

	print("vmdisp: %dx%d XRGB32 at %lux\n", Vmdwidth, Vmdheight, (ulong)Vmdguestaddr);
}

void
vmdispstart(void)
{
	if(vmdisp != nil)
		kproc("vmdisp", vmdispinput, nil, 0);
}
