/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/cdev.h>
#include <linux/cred.h>  // for current_uid();
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/init.h>    // included for __init and __exit macros
#include <linux/kernel.h>  // included for KERN_INFO
#include <linux/module.h>  // included for all kernel modules
#include <linux/mutex.h>   // for mutex lock
#include <linux/proc_fs.h>
#include <linux/random.h>  // for get_random_u32
#include <linux/sched.h>   // task_struct requried for current_uid()
#include <linux/seq_file.h>
#include <linux/slab.h>  // for kzalloc/kfree
#include <linux/string.h>
#include <linux/uaccess.h>  // copy_to_user

#include "maze.h"

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static DEFINE_MUTEX(my_mutex_lock);

typedef struct {
    pid_t process_id;
    maze_t *maze;
} user_t;

static user_t *users[_MAZE_MAXUSER] = { NULL };

// ----------------- character device ----------------- //

static int mazemod_dev_open(struct inode *i, struct file *f) {
    printk(KERN_INFO "mazemod_dev_open: pid=%d, device opened.\n", current->pid);
    return 0;
}

static int mazemod_dev_close(struct inode *i, struct file *f) {
    // mutex_lock(&my_mutex_lock);
    for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (users[i] != NULL && users[i]->process_id == current->pid) {
            kfree(users[i]->maze);  // free the maze
            users[i]->maze = NULL;  // NULL the pointer to avoid dangling pointer
            kfree(users[i]);
            users[i] = NULL;
            printk(KERN_INFO "mazemod_dev_close: pid=%d, device closed.\n", current->pid);
            return 0;
        }
    }
    // mutex_unlock(&my_mutex_lock);
    printk(KERN_INFO "mazemod_dev_close: pid=%d, device not found.\n", current->pid);

    return 0;
}

// return a byte sequence of 25 bytes containing the content in int [ 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1 ].
static ssize_t mazemod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
    int i = 0;
    int maze_has_created = 0;
    for (; i < _MAZE_MAXUSER; i++) {
        if (users[i] != NULL && users[i]->process_id == current->pid) {
            maze_has_created = 1;
            break;
        }
    }
    if (maze_has_created == 0) return -EBADFD;

    maze_t *maze = users[i]->maze;
    int size = maze->h * maze->w;

    char *returnBuf = kzalloc(size * sizeof(char), GFP_KERNEL); // should be char* instead of int* to avoid 4 bytes padding
    int k = 0;
    for (int row = 0; row < maze->h; row++) {
        for (int col = 0; col < maze->w; col++) {
            if (maze->blk[row][col] == '#') {
                returnBuf[k] = 1;   // char 1 (it's still 1 in char type)
            } else {
                returnBuf[k] = 0;   // char 0
            }
            k++;
        }
    }

    if (copy_to_user(buf, returnBuf, sizeof(char) * size)) {
        pr_alert("mazemod_dev_read: copy_to_user failed\n");
        return -EBUSY;
    }

    kfree(returnBuf);
    returnBuf = NULL;

    return size;
}

// batch player movement
static ssize_t mazemod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    // printk(KERN_INFO "mazemod_dev_write: write %zu bytes @ %llu.\n", len, *off);
    
    if (len % sizeof(coord_t) != 0) return -EINVAL;
    
    int movement_count = len / sizeof(coord_t);

    // copy from user space buf to batch_move_buf with len
    coord_t *batch_move_buf = kzalloc(len, GFP_KERNEL);
    
    if (copy_from_user(batch_move_buf, buf, len)) {
        pr_alert("mazemod_dev_write: copy_from_user failed\n");
        kfree(batch_move_buf);
        batch_move_buf = NULL;
        return EBUSY;
    }

    int i = 0;
    int maze_has_created = 0;
    for (; i < _MAZE_MAXUSER; i++) {
        if (users[i] != NULL && users[i]->process_id == current->pid) {
            maze_has_created = 1;
            break;
        }
    }
    if (maze_has_created == 0) {
        kfree(batch_move_buf);
        batch_move_buf = NULL;
        return -EBADFD;
    } 

    maze_t *maze = users[i]->maze;
    for (int move_idx = 0; move_idx < movement_count; move_idx++) {
        coord_t coord = batch_move_buf[move_idx];
        // printk("move %d: (%d, %d)\n", move_idx, coord.x, coord.y);
        int x = maze->cx + coord.x;
        int y = maze->cy + coord.y;
        if (x < 0 || x >= maze->w || y < 0 || y >= maze->h) continue;
        if (maze->blk[y][x] != '.') continue;
        maze->cx = x;
        maze->cy = y;
    }

    kfree(batch_move_buf);
    batch_move_buf = NULL;
    return len;
}

static long create_maze(coord_t *coord, int free_user_id) {
    maze_t *maze = kzalloc(sizeof(maze_t), GFP_KERNEL);
    if (maze == NULL) return -ENOMEM;

    maze->w = coord->x;
    maze->h = coord->y;

    // Initialize the random start and end positions
    maze->sx = get_random_u32() % (maze->w - 2) / 2 + 1;
    maze->sy = get_random_u32() % (maze->h - 2) / 2 + 1;
    maze->cx = maze->sx;
    maze->cy = maze->sy;
    maze->ex = coord->x - 2;
    maze->ey = coord->y - 2;

    for (int i = 0; i < maze->w; i++) {
        maze->blk[0][i] = '#';            // Top wall
        maze->blk[maze->h - 1][i] = '#';  // Bottom wall
    }
    for (int i = 1; i < maze->h - 1; i++) {
        maze->blk[i][0] = '#';            // Left wall
        maze->blk[i][maze->w - 1] = '#';  // Right wall
    }

    // *** create random maze with valid road ***

    // make a valid road from start to end
    int sx = maze->sx;
    int sy = maze->sy;
    int ex = maze->ex;
    int ey = maze->ey;
    while (sx != ex || sy != ey) {
        maze->blk[sy][sx] = '.';

        int rand = get_random_u32() % 10;
        if (rand == 1 && sx > 2) {
            sx--;
            continue;
        } else if (rand == 2 && sx < maze->w - 2) {
            sx++;
            continue;
        } else if (rand == 3 && sy > 2) {
            sy--;
            continue;
        } else if (rand == 4 && sy < maze->h - 2) {
            sy++;
            continue;
        }
        int dx = ex - sx;
        int dy = ey - sy;
        if (dx > 0) {
            sx++;
        } else if (dy > 0) {
            sy++;
        } else if (dx < 0) {
            sx--;
        } else if (dy < 0) {
            sy--;
        }
    }

    // the other cells are randomly filled with walls or roads
    for (int i = 1; i < maze->h - 1; i++) {
        for (int j = 1; j < maze->w - 1; j++) {
            if (maze->blk[i][j] == '.') continue;
            maze->blk[i][j] = (get_random_u32() % 10) < 5 ? '#' : '.';  // 50% chance to be a wall
        }
    }
    // *** create random maze with valid road done ***

    user_t *user = kzalloc(sizeof(user_t), GFP_KERNEL);
    if (user == NULL) {
        kfree(maze);
        maze = NULL;
        return -ENOMEM;
    }
    user->process_id = current->pid;
    user->maze = maze;

    if (users[free_user_id] == NULL) {
        users[free_user_id] = user;
        return 0;
    }
    printk(KERN_INFO "maze created: failed %d x %d, start: (%d, %d), current: (%d, %d).\n", maze->w, maze->h, maze->sx, maze->sy, maze->cx, maze->cy);

    return 0;
}

static long mazemod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
    // printk(KERN_INFO "mazemod: ioctl cmd=%u arg=%lu.\n", cmd, arg);

    switch (cmd) {
        case MAZE_CREATE:
            mutex_lock(&my_mutex_lock);
            int free_user_id = 0;
            for (; free_user_id < _MAZE_MAXUSER; free_user_id++) {
                if (users[free_user_id] == NULL) break;
            }
            if (free_user_id == _MAZE_MAXUSER) {
                mutex_unlock(&my_mutex_lock);
                return -ENOMEM;
            }

            coord_t coord;
            if (copy_from_user(&coord, (coord_t __user *)arg, sizeof(coord_t))) {
                mutex_unlock(&my_mutex_lock);
                return -EBUSY;
            }

            if (coord.x > _MAZE_MAXX || coord.y > _MAZE_MAXY || coord.x < 3 || coord.y < 3) {
                mutex_unlock(&my_mutex_lock);
                return -EINVAL;
            }
            long ret = create_maze(&coord, free_user_id);

            mutex_unlock(&my_mutex_lock);
            return ret;

        case MAZE_RESET:
            for (int i = 0; i < _MAZE_MAXUSER; i++) {
                if (users[i] != NULL && users[i]->process_id == current->pid) {
                    users[i]->maze->cx = users[i]->maze->sx;
                    users[i]->maze->cy = users[i]->maze->sy;
                    return 0;
                }
            }
            return -ENOENT;

        case MAZE_DESTROY:
            for (int i = 0; i < _MAZE_MAXUSER; i++) {
                if (users[i] != NULL && users[i]->process_id == current->pid) {
                    kfree(users[i]->maze);
                    users[i]->maze = NULL;
                    kfree(users[i]);
                    users[i] = NULL;
                    return 0;
                }
            }
            return -ENOENT;

        case MAZE_GETSIZE:
            for (int i = 0; i < _MAZE_MAXUSER; i++) {
                if (users[i] != NULL && users[i]->process_id == current->pid) {
                    coord_t size;
                    size.x = users[i]->maze->w;
                    size.y = users[i]->maze->h;
                    if (copy_to_user((coord_t __user *)arg, &size, sizeof(coord_t))) {
                        return -EBUSY;
                    }
                    return 0;
                }
            }

            return -ENOENT;

        case MAZE_MOVE:
            if (copy_from_user(&coord, (coord_t __user *)arg, sizeof(coord_t))) {
                return -EBUSY;
            }

            // Valid values: (-1, 0), (1, 0), (0, -1), and (0, 1)
            if ((coord.x == -1 && coord.y == 0) || (coord.x == 1 && coord.y == 0) 
             || (coord.x == 0 && coord.y == -1) || (coord.x == 0 && coord.y == 1)) {  // valid
            } else {
                // Invalid movement -> ignore and return zero (OK)
                return 0;
            }

            for (int i = 0; i < _MAZE_MAXUSER; i++) {
                if (users[i] != NULL && users[i]->process_id == current->pid) {
                    maze_t *maze = users[i]->maze;
                    int x = maze->cx + coord.x;
                    int y = maze->cy + coord.y;
                    // Invalid movement -> ignore and return zero (OK)
                    if (x < 0 || x >= maze->w || y < 0 || y >= maze->h) return 0;
                    if (maze->blk[y][x] == '#') return 0;

                    maze->cx = x;
                    maze->cy = y;
                    return 0;
                }
            }
            return -ENOENT;

        case MAZE_GETPOS:
            for (int i = 0; i < _MAZE_MAXUSER; i++) {
                if (users[i] != NULL && users[i]->process_id == current->pid) {
                    coord_t pos;
                    pos.x = users[i]->maze->cx;
                    pos.y = users[i]->maze->cy;
                    if (copy_to_user((coord_t __user *)arg, &pos, sizeof(coord_t))) {
                        return -EBUSY;
                    }
                    // printk(KERN_INFO "getpos: (%d, %d).\n", pos.x, pos.y);
                    return 0;
                }
            }
            return -ENOENT;

        case MAZE_GETSTART:
            for (int i = 0; i < _MAZE_MAXUSER; i++) {
                if (users[i] != NULL && users[i]->process_id == current->pid) {
                    coord_t start;
                    start.x = users[i]->maze->sx;
                    start.y = users[i]->maze->sy;
                    if (copy_to_user((coord_t __user *)arg, &start, sizeof(coord_t))) {
                        return -EBUSY;
                    }
                    return 0;
                }
            }
            return -ENOENT;

        case MAZE_GETEND:
            for (int i = 0; i < _MAZE_MAXUSER; i++) {
                if (users[i] != NULL && users[i]->process_id == current->pid) {
                    coord_t end;
                    end.x = users[i]->maze->ex;
                    end.y = users[i]->maze->ey;
                    if (copy_to_user((coord_t __user *)arg, &end, sizeof(coord_t))) {
                        return -EBUSY;
                    }
                    return 0;
                }
            }
            return -ENOENT;

        default:
            return -EINVAL;
    }

    return 0;
}

static const struct file_operations mazemod_dev_fops = {
    .owner = THIS_MODULE,
    .open = mazemod_dev_open,
    .read = mazemod_dev_read,
    .write = mazemod_dev_write,
    .unlocked_ioctl = mazemod_dev_ioctl,
    .release = mazemod_dev_close};

// ----------------- proc file system ----------------- //

static int maze_proc_show(struct seq_file *m, void *v) {
    int i;
    for (i = 0; i < _MAZE_MAXUSER; i++) {
        if (users[i] == NULL) {
            seq_printf(m, "#%02d: vacancy.\n\n", i);
        } else {
            maze_t *maze = users[i]->maze;
            seq_printf(m, "#%02d: pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n",
                       i, users[i]->process_id, maze->w, maze->h, maze->sx, maze->sy, maze->ex, maze->ey, maze->cx, maze->cy);
            int j, k;
            for (j = 0; j < maze->h; j++) {
                seq_printf(m, "- %03d: ", j);
                for (k = 0; k < maze->w; k++) {
                    char c;
                    if (j == maze->cy && k == maze->cx)  // may be `*` if it's overlapped with start or end
                        c = '*';
                    else if (j == maze->ey && k == maze->ex)
                        c = 'E';
                    else if (j == maze->cy && k == maze->cx)
                        c = 'S';
                    else
                        c = maze->blk[j][k];
                    seq_printf(m, "%c", c);
                }
                seq_printf(m, "\n");
            }
            seq_printf(m, "\n");
        }
    }
    return 0;
}

static int mazemod_proc_open(struct inode *inode, struct file *file) {
    return single_open(file, maze_proc_show, NULL);
}

static const struct proc_ops mazemod_proc_fops = {
    .proc_open = mazemod_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static char *mazemod_devnode(const struct device *dev, umode_t *mode) {
    if (mode == NULL) return NULL;
    *mode = 0666;
    return NULL;
}

static int __init mazemod_init(void) {
    // create char dev
    if (alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
        return -1;
    if ((clazz = class_create("upclass")) == NULL)
        goto release_region;
    clazz->devnode = mazemod_devnode;

    // create device node in /dev 會自動產生 /dev/maze
    if (device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
        goto release_class;

    cdev_init(&c_dev, &mazemod_dev_fops);
    if (cdev_add(&c_dev, devnum, 1) == -1)
        goto release_device;

    // create proc entry for /proc 會自動產生 /proc/maze
    proc_create("maze", 0, NULL, &mazemod_proc_fops);

    // printk(KERN_INFO "mazemod: initialized.\n");
    return 0;  // Non-zero return means that the module couldn't be loaded.

release_device:
    device_destroy(clazz, devnum);

release_class:
    class_destroy(clazz);

release_region:
    unregister_chrdev_region(devnum, 1);
    return -1;
}

// when remove module
static void __exit mazemod_cleanup(void) {
    for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (users[i] != NULL) {
            kfree(users[i]->maze);
            users[i]->maze = NULL;
            kfree(users[i]);
            users[i] = NULL;
        }
    }

    remove_proc_entry("maze", NULL);

    cdev_del(&c_dev);
    device_destroy(clazz, devnum);
    class_destroy(clazz);
    unregister_chrdev_region(devnum, 1);

    // printk(KERN_INFO "mazemod: cleaned up.\n");
}

module_init(mazemod_init);
module_exit(mazemod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yu-Hsuan, Lo");
MODULE_DESCRIPTION("The unix programming course lab 2.");

