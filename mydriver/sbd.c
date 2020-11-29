#include <linux/blkdev.h>
#include <linux/module.h>

#include "sbd.h"

// This mutex is for open device.
static DEFINE_MUTEX(sblk_mutex);

static int s_maxsectors;
module_param(s_maxsectors, int, 0644);
MODULE_PARM_DESC(s_maxsectors, "When nonzero, set the maximum number of sectors per I/O request");

static blk_status_t sblk_queue_rq(struct blk_mq_hw_ctx *hctx, const struct blk_mq_queue_data *bd)
{
    sdev_t *d = hctx->queue->queuedata;

    spin_lock_irq(&d->lock);
    list_add_tail(&bd->rq->queuelist, &d->rq_list);
    spin_unlock_irq(&d->lock);

    return BLK_STS_OK;
}

static void sblk_queue_complete(struct request *req)
{
    sblk_req_t *sbr = blk_mq_rq_to_pdu(req);
    blk_mq_end_request(req, sbr->status);
}

static const struct blk_mq_ops sblk_mq_ops = {
    .queue_rq = sblk_queue_rq,
    .complete = sblk_queue_complete};

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

    spin_unlock_irqrestore(&d->lock, flags);
};

static const struct block_device_operations s_bdops = {
    .open = sblk_open,
    .release = sblk_release,
    .owner = THIS_MODULE,
};

/**
 * generic disk allocate 
 */
int sblk_gdalloc(void *vp)
{
    sdev_t *d = vp;
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
    set->cmd_size = sizeof(sblk_req_t);
    set->nr_hw_queues = 1;
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
    rq->backing_dev_info->ra_pages = READ_AHEAD / PAGE_SIZE;
    d->blkq = rq;
    rq->queuedata = d;
    d->disk = gd;
    if (s_maxsectors)
        blk_queue_max_hw_sectors(rq, s_maxsectors);
    gd->queue = rq;
    gd->major = S_MAJOR;
    gd->first_minor = d->sysminor;
    gd->fops = &s_bdops;
    gd->private_data = d;
    set_capacity(gd, d->nr_sectors);
    snprintf(gd->disk_name, sizeof gd->disk_name, "sblka");

    spin_unlock_irqrestore(&d->lock, flags);

    add_disk(d->disk);
    return 0;

err_disk:
    put_disk(gd);
err_tagset:
    blk_mq_free_tag_set(set);
err_end:
    return err;
}

void sblk_gddelete(void *vp)
{
    sdev_t *d = vp;
    if (d->disk)
    {
        del_gendisk(d->disk);
    }
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
    sblk_gddelete(sblk_dev);
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

    printk(KERN_INFO "sblk inited");
    return 0;
}

static void __exit sdev_exit(void)
{
    unregister_blkdev(S_MAJOR, DEVICE_NAME);
    sblk_exit();
}

module_init(sdev_init);
module_exit(sdev_exit);

MODULE_DESCRIPTION("self block driver");
MODULE_LICENSE("GPL");
