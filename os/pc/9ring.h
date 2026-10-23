/*
 * 9ring.h - 9vm host 9P shared-ring layout.
 *
 * Must match sys/include/9ring.h in the Harvey tree and the P9HostShared
 * structure 9vm places at the top of guest RAM.  The host declares the
 * structures with uint8_t..uint64_t and 64-byte alignment attributes; the
 * definitions below use explicit padding because 8c has no attributes.
 */

#define P9_RING_SIZE	256
#define P9_RING_MASK	(P9_RING_SIZE - 1)

#define P9_HOST_MAGIC	0x39524853
#define P9_HOST_VERSION	1
#define P9_HOST_SLOTS	8
#define P9_HOST_MSIZE	32768
#define P9_HOST_REGION_SIZE	(2*1024*1024)

typedef struct P9Slot P9Slot;
struct P9Slot
{
	ushort	tag;
	uchar	type;
	uchar	flags;
	ulong	fid;
	uvlong	offset;
	ulong	count;
	ulong	pad;
	uvlong	buf_addr;
};

typedef struct P9TRing P9TRing;
struct P9TRing
{
	ulong	head;
	uchar	pad0[60];
	ulong	tail;
	uchar	pad1[60];
	P9Slot	slots[P9_RING_SIZE];
};

typedef struct P9Comp P9Comp;
struct P9Comp
{
	ushort	tag;
	uchar	type;
	uchar	status;
	ulong	count;
	uvlong	result;
};

typedef struct P9RRing P9RRing;
struct P9RRing
{
	ulong	head;
	uchar	pad0[60];
	ulong	tail;
	uchar	pad1[60];
	P9Comp	comps[P9_RING_SIZE];
};

typedef struct P9Channel P9Channel;
struct P9Channel
{
	P9TRing	t;
	P9RRing	r;
};

typedef struct P9HostBuffer P9HostBuffer;
struct P9HostBuffer
{
	uchar	request[P9_HOST_MSIZE];
	uchar	response[P9_HOST_MSIZE];
};

typedef struct P9HostShared P9HostShared;
struct P9HostShared
{
	ulong		magic;
	ulong		version;
	uchar		pad[56];
	P9Channel	channel;
	P9HostBuffer	buffer[P9_HOST_SLOTS];
};
