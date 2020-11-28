#include <linux/init.h>
#include <linux/module.h>

static int init(void)
{
    printk(KERN_INFO "My Driver Init.");
    return 0;
}

static void exit(void)
{
    printk(KERN_INFO "My Driver Exit.");
}

module_init(init);
module_exit(exit);