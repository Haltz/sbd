#include <linux/blkdev.h>
#include <linux/module.h>

#include "sbd.h"

// This mutex is for open device.
static DEFINE_MUTEX(sblk_mutex);

static int s_maxsectors;
module_param(s_maxsectors, int, 0644);
MODULE_PARM_DESC(s_maxsectors, "When nonzero, set the maximum number of sectors per I/O request");

static void sbd_block_transfer(sdev_t *dev, size_t start, size_t len, char *buffer, int dir)
{
    size_t cache_offset = start * 512;
    if (dir)
    {
        memcpy(dev->cache + cache_offset, buffer, len);
        pr_info("Write Try Good.");
    }
    else
    {
        memcpy(dev->cache + cache_offset, buffer, len);
        pr_info("Read Try Good.");
    }
}

static blk_status_t sblk_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
    sdev_t *sblk = hctx->queue->queuedata;
    struct request *req = bd->rq;
    sbd_cmd_t *cmd = blk_mq_rq_to_pdu(req);
    // unsigned long flags;
    // unsigned int num;
    // int qid = hctx->queue_num;
    u32 type;

    // BUG_ON(req->nr_phys_segments + 2 > vblk->sg_elems);
    unsigned int req_op = req_op(req);
    switch (req_op)
    {
    case REQ_OP_READ:
    case REQ_OP_WRITE:
        type = 0;
        break;
    case REQ_OP_FLUSH:
        type = S_BLK_T_FLUSH;
        break;
    case REQ_OP_DISCARD:
        type = S_BLK_T_DISCARD;
        break;
    case REQ_OP_WRITE_ZEROES:
        type = S_BLK_T_WRITE_ZEROES;
        break;
    case REQ_OP_DRV_IN:
        type = S_BLK_T_GET_ID;
        break;
    default:
        // WARN_ON_ONCE(1);
        printk(KERN_ERR "OP_ERR: %s", blk_op_str(req_op(req)));
        return BLK_STS_IOERR;
    }

    blk_mq_start_request(req);

    printk(KERN_INFO "OP_INFO: %s", blk_op_str(req_op(req)));
    if (type)
    {
        pr_err("OP: NOT READ OR WRITE. NOT SUPPORTED.");
        blk_mq_end_request(req, BLK_STS_NOTSUPP);
        return BLK_STS_NOTSUPP;
    }

    struct bio *next = req->bio;
    while (next)
    {
        int dir = req_op(req) == REQ_OP_READ ? 0 : 1;

        struct bio_vec bvec;
        struct bvec_iter i;

        bio_for_each_segment(bvec, req->bio, i)
        {
            sector_t sector = i.bi_sector;
            char *buffer = kmap_atomic(bvec.bv_page);
            unsigned long offset = bvec.bv_offset;
            size_t len = bvec.bv_len;

            sbd_block_transfer(sblk, sector, len, buffer + offset, dir);

            kunmap_atomic(buffer);
        }

        next = next->bi_next;
    }

    blk_mq_end_request(req, BLK_STS_OK);

    return BLK_STS_OK;
}

// static void sblk_queue_complete(struct request *req)
// {
//     sbd_cmd_t *cmd = blk_mq_rq_to_pdu(req);
//     blk_mq_end_request(req, cmd->status);
// }

static const struct blk_mq_ops sblk_mq_ops = {
    .queue_rq = sblk_queue_rq,
    // .complete = sblk_queue_complete,
};

/**
 * Implement block_device_operation definitons 
 */
static int sblk_open(struct block_device *bdev, fmode_t mode)
{
    sdev_t *d = bdev->bd_disk->private_data;
    ulong flags;

    mutex_lock(&sblk_mutex);
    spin_lock_irqsave(&d->lock, flags);

    d->nopen++;
    printk(KERN_INFO "REFCOUNT++: %d", d->nopen);

    spin_unlock_irqrestore(&d->lock, flags);
    mutex_unlock(&sblk_mutex);

    return 0;
};

static void sblk_release(struct gendisk *disk, fmode_t mode)
{
    sdev_t *d = disk->private_data;
    ulong flags;

    spin_lock_irqsave(&d->lock, flags);

    d->nopen--;
    printk(KERN_INFO "REFCOUNT--: %d", d->nopen);

    spin_unlock_irqrestore(&d->lock, flags);
};

// This function is called when accessing inode
static int sblk_rw_page(struct block_device *bdev, sector_t sector, struct page *page, unsigned int req_op)
{
    sdev_t *d = bdev->bd_disk->private_data;
    pr_info("rw_page call");
    switch (req_op)
    {
    case REQ_OP_READ:
        pr_info("Read");
        break;
    case REQ_OP_WRITE:
        pr_info("Write");
        break;
    default:
        pr_err("not supported");
    }
    return 0;
}

static int sblk_ioctl(struct block_device *bdev, fmode_t mode, unsigned cmd, unsigned long arg)
{
    pr_info("ioctl call");
    return 0;
}

static const struct block_device_operations s_bdops = {
    .open = sblk_open,
    .release = sblk_release,
    .rw_page = sblk_rw_page,
    .ioctl = sblk_ioctl,
    .owner = THIS_MODULE,
};

/**
 * generic disk allocate 
 */
int sblk_gdalloc(void *vp)
{
    sdev_t *d = sblk_dev;
    struct gendisk *gd;
    struct request_queue *rq;
    struct blk_mq_tag_set *set;
    ulong flags;
    int err;

    gd = alloc_disk(S_PARTITIONS);
    if (gd == NULL)
    {
        pr_err("sblk: can't allocate gd structure.");
        err = -ENOMEM;
        goto err_end;
    }

    set = &d->tag_set;
    set->ops = &sblk_mq_ops;
    set->cmd_size = sizeof(sbd_cmd_t);
    set->nr_hw_queues = 1;
    set->nr_maps = 1;
    set->queue_depth = 128;
    set->numa_node = NUMA_NO_NODE;
    set->flags = BLK_MQ_F_SHOULD_MERGE;
    err = blk_mq_alloc_tag_set(set);
    if (err)
    {
        pr_err("sblk: cannot allocate tag set.");
        err = -ENOMEM;

        goto err_tagset;
    }

    rq = blk_mq_init_queue(set);
    if (IS_ERR(rq))
    {
        blk_mq_free_tag_set(set);
        pr_err("sblk: cannot allocate block queue");
        err = -ENOMEM;
        goto err_disk;
    }

    spin_lock_irqsave(&d->lock, flags);
    // WARN_ON(!(d->flags & DEVFL_GD_NOW));
    // WARN_ON(!(d->flags & DEVFL_GDALLOC));
    // WARN_ON(d->flags & DEVFL_TKILL);
    // WARN_ON(d->gd);
    // WARN_ON(d->flags & DEVFL_UP);

    // set max sectors queue can hold
    blk_queue_max_hw_sectors(rq, BLK_DEF_MAX_SECTORS);
    d->blkq = rq;
    rq->queuedata = d;
    d->disk = gd;

    gd->queue = rq;
    gd->major = S_MAJOR;
    gd->first_minor = d->sysminor;
    gd->fops = &s_bdops;
    gd->private_data = d;
    // set_capacity(gd, d->nr_sectors);
    sblk_dev->cache = kzalloc(2 * MB, GFP_KERNEL);
    if (!sblk_dev->cache)
    {
        err = -ENOMEM;
        goto err_disk;
    }
    set_capacity(gd, 2 * MB / 512);
    snprintf(gd->disk_name, sizeof(gd->disk_name), "sb%d", '0' + d->nopen);

    spin_unlock_irqrestore(&d->lock, flags);

    add_disk(d->disk);
    return 0;

err_tagset:
    // blk_mq_free_tag_set(set);
err_disk:
    put_disk(gd);
err_end:
    return err;
}

/**
 * blk init and exit part.
 */
int sblk_init(void)
{
    return sblk_gdalloc(sblk_dev);
}

void sblk_exit(void)
{
    del_gendisk(sblk_dev->disk);
    blk_cleanup_queue(sblk_dev->disk->queue);
    blk_mq_free_tag_set(&sblk_dev->tag_set);

    mutex_lock(&sblk_mutex);

    put_disk(sblk_dev->disk);

    mutex_unlock(&sblk_mutex);

    return;
}

/**
 * dev init and exit part.
 * */
static int __init sdev_init(void)
{
    int ret = sblk_init();
    if (ret)
    {
        sblk_exit();
        printk(KERN_ERR "sblk init fail");
        return ret;
    }

    ret = register_blkdev(S_MAJOR, DEVICE_NAME);

    if (ret < 0)
    {
        sblk_exit();
        printk(KERN_ERR "sblk register fail");
        return ret;
    }

    printk(KERN_INFO "sblk inited\n");
    return 0;
}

static void __exit sdev_exit(void)
{
    unregister_blkdev(S_MAJOR, DEVICE_NAME);
    sblk_exit();

    printk(KERN_INFO "sbd: sblk exited\n");
}

module_init(sdev_init);
module_exit(sdev_exit);

MODULE_DESCRIPTION("self block driver");
MODULE_LICENSE("GPL");
