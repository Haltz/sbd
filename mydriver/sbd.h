#include <linux/blk-mq.h>

#define S_MAJOR 244
#define S_MINORS 16
#define DEVICE_NAME "sdriver"

#ifndef S_PARTITIONS
#define S_PARTITIONS (16)
#endif

enum
{
    KB = 1024,
    MB = KB * KB,
    READ_AHEAD = 2 * MB
};

enum
{
    DEFAULTBCNT = 2 * 512,
    MIN_BUFS = 16,
    NTARGETS = 4,
    NAOEIFS = 8,
    NSKBPOOLMAX = 256,
    NFACTIVE = 61,

    TIMERTICK = 10,
    RTTSCALE = 8,
    RTTDSCALE = 3
};

enum
{
    DEVFL_UP = 1,
    DEVFL_TKILL = (1 << 1),
    DEVFL_EXT = (1 << 2),
    DEVFL_GDALLOC = (1 << 3),
    DEVFL_GD_NOW = (1 << 4),
    DEVFL_KICKNAME = (1 << 5),
    DEVFL_NEWSIZE = (1 << 6),
    DEVFL_FREEING = (1 << 7),
    DEVFL_FREED = (1 << 8)
};

typedef struct sblk_req_s
{
    blk_status_t status;
} sblk_req_t;

typedef struct sdev_s
{
    u16 flags;
    u16 nopen;
    ulong sysminor;

    struct gendisk *disk;

    struct request_queue *rq;
    struct blk_mq_tag_set tag_set;

    spinlock_t lock;
    struct list_head rq_list;

    struct request_queue *blkq;

    sector_t nr_sectors;

    char ident[512];

} sdev_t;

sdev_t sblock_dev;
sdev_t *sblk_dev = &sblock_dev;

static int sblk_init(void);
static void sblk_exit(void);
int sblk_gdalloc(void *);

static int sdev_init(void);
static void sdev_exit(void);