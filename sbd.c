#include <linux/blkdev.h>
#include <linux/module.h>

#include "sbd.h"

// This mutex is for opening device.
static DEFINE_MUTEX(sblk_mutex);

static int s_maxsectors;
module_param(s_maxsectors, int, 0644);
MODULE_PARM_DESC(
    s_maxsectors,
    "When nonzero, set the maximum number of sectors per I/O request");

static void sbd_block_transfer(sdev_t *dev, size_t start, size_t len,
                               char *buffer, int dir) {
  size_t cache_offset = start * 512;
  if (cache_offset + len > 2 * MB) {
    pr_err("sbd: exceed capacity.");
    return;
  }

  if (dir) {
    // int i;
    // for (i = 0; i < 64; i++) {
    //   pr_info("[sbd data]: 0x%lx\n", buffer[i]);
    // }
    memcpy(dev->cache + cache_offset, buffer, len);
  } else {
    // int i;
    // for (i = 0; i < 64; i++) {
    //   pr_info("[sbd data]: 0x%lx\n", buffer[i]);
    // }
    memcpy(buffer, dev->cache + cache_offset, len);
  }
}

static blk_status_t sblk_queue_rq(struct blk_mq_hw_ctx *hctx,
                                  const struct blk_mq_queue_data *bd) {
  sdev_t *sblk = hctx->queue->queuedata;
  struct request *req = bd->rq;
  sbd_cmd_t *cmd = blk_mq_rq_to_pdu(req);
  // unsigned long flags;
  // unsigned int num;
  // int qid = hctx->queue_num;
  u32 type;

  // BUG_ON(req->nr_phys_segments + 2 > vblk->sg_elems);
  unsigned int req_op = req_op(req);
  switch (req_op) {
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
    pr_err("Operation: %s not supported.", blk_op_str(req_op(req)));
    return BLK_STS_IOERR;
  }

  blk_mq_start_request(req);

  pr_info("Operation is %s.", blk_op_str(req_op(req)));

  if (type) {
    pr_err("Operation: %s not supported.", blk_op_str(req_op(req)));
    blk_mq_end_request(req, BLK_STS_NOTSUPP);
    return BLK_STS_NOTSUPP;
  }

  struct bio *next = req->bio;
  int dir = req_op(req) == REQ_OP_READ ? 0 : 1;

  while (next) {

    struct bio_vec bvec;
    struct bvec_iter i;

    bio_for_each_segment(bvec, req->bio, i) {
      sector_t sector = i.bi_sector;
      char *buffer = kmap_atomic(bvec.bv_page);
      unsigned long offset = bvec.bv_offset;
      size_t len = bvec.bv_len;

      sbd_block_transfer(sblk, sector, len, buffer + offset, dir);

      pr_info("[sbd]: sector 0x%x\t len: 0x%x\t buffer: 0x%x\t offset:0x%x",
              sector, len, buffer, offset);

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
static int sblk_open(struct block_device *bdev, fmode_t mode) {
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

static void sblk_release(struct gendisk *disk, fmode_t mode) {
  sdev_t *d = disk->private_data;
  ulong flags;

  spin_lock_irqsave(&d->lock, flags);

  d->nopen--;
  printk(KERN_INFO "REFCOUNT--: %d", d->nopen);

  spin_unlock_irqrestore(&d->lock, flags);
};

// This function is called when accessing inode
static int sblk_rw_page(struct block_device *bdev, sector_t sector,
                        struct page *page, unsigned int req_op) {
  sdev_t *d = bdev->bd_disk->private_data;
  char *buffer = kmap_atomic(page);
  char *cache_start = d->cache + sector * 512;
  char *cache_end = d->cache + 2 * MB / 8;
  bool is_write = req_op == REQ_OP_READ ? 0 : 1;
  size_t page_ssize = page_size(page);
  int err = 0;

  pr_info("cache: %lx\t sector: %lx\t cache_start: %lx\t page_size: %lx\t "
          "access_mem: %lx\t cache_end: %lx",
          d->cache, sector, cache_start, page_ssize, cache_start + page_ssize,
          cache_end);

  if (is_write) {
    if (cache_start + page_ssize > cache_end) {
      err = -1;
      goto end;
    }
    memcpy(cache_start, buffer, page_ssize);
    pr_info("Write Page");
  } else {
    if (cache_start + page_ssize > cache_end) {
      err = -1;
      goto end;
    }
    memcpy(buffer, cache_start, page_ssize);
    pr_info("Read Page");
  }

end:
  page_endio(page, is_write, err);
  pr_err("Cross Edge.");
  return err;
}

static int sblk_ioctl(struct block_device *bdev, fmode_t mode, unsigned cmd,
                      unsigned long arg) {
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
int sblk_gdalloc(void *vp) {
  sdev_t *d = sblk_dev;
  struct gendisk *gd;
  struct request_queue *rq;
  struct blk_mq_tag_set *set;
  ulong flags;
  int err;

  gd = alloc_disk(S_PARTITIONS);
  if (gd == NULL) {
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
  if (err) {
    pr_err("sblk: cannot allocate tag set.");
    err = -ENOMEM;

    goto err_tagset;
  }

  rq = blk_mq_init_queue(set);
  if (IS_ERR(rq)) {
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
  sblk_dev->cache = kzalloc(2 * MB, GFP_ATOMIC);
  if (!sblk_dev->cache) {
    err = -ENOMEM;
    goto err_disk;
  }
  set_capacity(gd, 2 * MB / 512);
  snprintf(gd->disk_name, sizeof(gd->disk_name), "sb%c", '0' + d->nopen);

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
int sblk_init(void) { return sblk_gdalloc(sblk_dev); }

void sblk_exit(void) {
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
static int __init sdev_init(void) {
  int ret = sblk_init();
  if (ret) {
    sblk_exit();
    printk(KERN_ERR "sblk init fail");
    return ret;
  }

  ret = register_blkdev(S_MAJOR, DEVICE_NAME);

  if (ret < 0) {
    sblk_exit();
    printk(KERN_ERR "sblk register fail");
    return ret;
  }

  printk(KERN_INFO "sblk inited\n");
  return 0;
}

static void __exit sdev_exit(void) {
  unregister_blkdev(S_MAJOR, DEVICE_NAME);
  sblk_exit();

  printk(KERN_INFO "sbd: sblk exited\n");
}

module_init(sdev_init);
module_exit(sdev_exit);

MODULE_DESCRIPTION("self block driver");
MODULE_LICENSE("GPL");
