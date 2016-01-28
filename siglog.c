/* Record kill system calls in /proc/siglog
 * Useful for kernels without or with ancient ftrace support
 *
 * Copyright (C) 2016 Norbert Federa <norbert.federa@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/slab.h>

#define MAXLOGENTRIES 10000

MODULE_AUTHOR ("Norbert Federa <norbert.federa@gmail.com>");
MODULE_DESCRIPTION("Record kill system calls in /proc/siglog");
MODULE_LICENSE("GPL");

static char *sctaddress = NULL;

module_param(sctaddress, charp, S_IRUGO);
MODULE_PARM_DESC(sctaddress, "Address of the system call table");

struct siglog_t {
	struct timespec time;
	pid_t spid;
	pid_t stid;
	uid_t suid;
	pid_t tpid;
	int   snum;
	int   rval;
	char  scomm[TASK_COMM_LEN];
	char  tcomm[TASK_COMM_LEN];
};

struct siglog_t siglog[MAXLOGENTRIES];

atomic_t siglog_cnt = ATOMIC_INIT(0);

extern struct timezone sys_tz;

static void **syscall_table;

static int (*orig_sys_kill)(pid_t pid, int sig);



static int siglog_proc_show(struct seq_file *sf, void *v) {
	int i = 0;
	int c = 0;
	struct tm tm;
	unsigned int cnt = atomic_read(&siglog_cnt);
	int tzoffset = sys_tz.tz_minuteswest * -60;

	if (cnt > MAXLOGENTRIES) {
		i = cnt % MAXLOGENTRIES;
		cnt = MAXLOGENTRIES;
	}

	for (c = 0; c < cnt; c++) {
		time_to_tm(siglog[i].time.tv_sec, tzoffset, &tm);
		siglog[i].scomm[TASK_COMM_LEN-1] = 0;
		siglog[i].tcomm[TASK_COMM_LEN-1] = 0;
		seq_printf(sf, "%lu-%02d-%02d/%02d:%02d:%02d/%09lu: sig %02d from %05d:%05d [%-15s] (uid:%05d) to %6d [%-15s] returned %d\n",
				tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec,
				siglog[i].time.tv_nsec,
				siglog[i].snum,
				siglog[i].spid, siglog[i].stid, siglog[i].scomm,
				siglog[i].suid,
				siglog[i].tpid, siglog[i].tcomm,
				siglog[i].rval);

		if (++i >= MAXLOGENTRIES) {
			i = 0;
		}
	}
	return 0;
}

static int siglog_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, siglog_proc_show, NULL);
}

static const struct file_operations siglog_proc_fops = {
	.open       = siglog_proc_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = single_release,
};


static struct file* siglog_file_open(const char *filename, int flags, int mode) {
	struct file *fs = NULL;
	mm_segment_t orgfs;

	if (!filename || !*filename) {
		return NULL;
	}

	orgfs = get_fs();
	set_fs(KERNEL_DS);
	fs = filp_open(filename, flags, mode);
	set_fs(orgfs);
	if (IS_ERR(fs)) {
		return NULL;
	}
	return fs;
}

static ssize_t siglog_file_read(struct file *fs, void *buf, size_t count) {
	mm_segment_t orgfs;
	ssize_t ret;

	if (!fs || !fs->f_op || !fs->f_op->read) {
		return -1;
	}

	orgfs = get_fs();
	set_fs(KERNEL_DS);

	ret = fs->f_op->read(fs, buf, count, &fs->f_pos);

	set_fs(orgfs);
	return ret;
}

static void siglog_file_close(struct file *fs) {
    filp_close(fs, NULL);
}

static unsigned long **get_sys_call_table(unsigned long ptr) {
	unsigned long *p = (unsigned long *)ptr;

	if (p && p[__NR_close] == (unsigned long)sys_close) {
		return (unsigned long **)p;
	}

	return NULL;
}

static struct siglog_t *get_siglog_slot(void) {
	unsigned int cnt = atomic_inc_return(&siglog_cnt);
	unsigned int pos = (cnt - 1) % MAXLOGENTRIES;
	memset(&siglog[pos], 0, sizeof(struct siglog_t));
	return &siglog[pos];
}

static void copy_task_comm_via_pid(char *buffer, int pid) {
	struct pid *ps = NULL;
	struct task_struct *ts = NULL;

	ps = find_get_pid(pid);
	if (ps) {
		rcu_read_lock();
		ts = pid_task(ps, PIDTYPE_PID);
		if (ts) {
			task_lock(ts);
			strncpy(buffer, ts->comm, TASK_COMM_LEN);
			task_unlock(ts);
		}
		rcu_read_unlock();
		put_pid(ps);
	}
}

static int hooked_sys_kill(pid_t pid, int sig) {
	struct siglog_t *log;

	/* set the following define to 0 if you want to spam the log with
           0 signals which are only used to check if a process is running or to test
           if the calling task has permission to send signals to another process */
#if 1
	if (sig == 0) {
		return orig_sys_kill(pid, sig);
	}
#endif

	log = get_siglog_slot();

	getnstimeofday(&log->time);
	log->spid = task_tgid_vnr(current);
	log->stid = task_pid_vnr(current);
#if defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) || LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	log->suid = current_uid().val;
#else
	log->suid = current_uid();
#endif
	log->tpid = pid;
	log->snum = sig;

	copy_task_comm_via_pid(log->scomm, log->spid);
	copy_task_comm_via_pid(log->tcomm, log->tpid);

	log->rval = orig_sys_kill(pid, sig);

	return log->rval;
}

static void *replace_system_call(int index, void *new_fn) {
	void *ret = NULL;
	void *orig_fn = NULL;
	int wp = 1;
	unsigned long cr0;
	unsigned long page;

#ifdef CONFIG_X86_32
	wp = boot_cpu_data.wp_works_ok ? 1 : 0;
#endif

	if (wp) {
		/* disable protected mode */
		cr0 = read_cr0();
		write_cr0(cr0 & ~0x10000);
	}

	page = PAGE_ALIGN(1 + (unsigned long)&syscall_table[index]) - PAGE_SIZE;

	if (set_memory_rw(page, 1)) {
		printk(KERN_DEBUG "siglog: set_memory_rw failed\n");
		goto out;
	}

	orig_fn = syscall_table[index];
	syscall_table[index] = new_fn;

	if (set_memory_ro(page, 1)) {
		printk(KERN_DEBUG "siglog: set_memory_ro failed\n");
		goto out;
	}

	ret = orig_fn;

out:
	if (wp) {
		/* enable protected mode */
		cr0 = read_cr0();
		write_cr0(cr0 | 0x10000);
	}

	return ret;
}

static unsigned long detect_system_call_table_address(void) {
	unsigned long sct = 0;
	struct file *fs = NULL;
	char *map = NULL;
	char *buf = NULL;
	char *p;
	size_t bufsz = 4 * 1024 * 1024;
	size_t mapsz = PATH_MAX;
	int r;

	if (!(buf = kzalloc(bufsz, GFP_KERNEL))) {
		printk(KERN_DEBUG "siglog: failed to allocate read buffer\n");
		goto out;
	}

	if (!(map = kzalloc(mapsz, GFP_KERNEL))) {
		printk(KERN_DEBUG "siglog: failed to allocate map buffer\n");
		goto out;
	}


	strncat(map, "/boot/System.map-", 17);
	strncat(map, utsname()->release, mapsz - strlen(utsname()->release) - 1);

	printk(KERN_DEBUG "siglog: using system map file [%s] for auto detection\n", map);

	if (!(fs = siglog_file_open(map, O_RDONLY, 0))) {
		goto out;
	}

	r = siglog_file_read(fs, buf, bufsz - 1);
	if (r < 1 * 1024 * 1024) {
		goto out;
	}

	if (!(p = strstr(buf, " R sys_call_table\n"))) {
		goto out;
	}

	*p = 0;
	if ((p - buf) < 18 || *(p - 17) != '\n') {
		goto out;
	}
	p -= 18;
	p[0] = '0';
	p[1] = 'x';

	sct = simple_strtoul(p, NULL, 16);

out:
	if (map) {
		kfree(map);
	}
	if (buf) {
		kfree(buf);
	}
	if (fs) {
		siglog_file_close(fs);
	}

	if (!sct) {
		printk(KERN_DEBUG "siglog: auto detection failed\n");
	} else {
		printk(KERN_DEBUG "siglog: auto detection succeeded: 0x%p\n", (void*)sct);
	}

	return sct;
}


static int __init siglog_init(void) {
	unsigned long sct;

	if (!sctaddress) {
		printk(KERN_DEBUG "siglog: sctaddress not specified, trying auto detection\n");
		if (!(sct = detect_system_call_table_address())) {
			printk(KERN_DEBUG "siglog: autodetection failed\n");
			return -EINVAL;
		}
	} else {
		sct = simple_strtoul(sctaddress, NULL, 16);
		printk(KERN_DEBUG "siglog: specified syscall table address: 0x%p\n", (unsigned long*)sct);
	}

	if (!(syscall_table = (void **)get_sys_call_table(sct))) {
		printk(KERN_DEBUG "siglog: could not verify the system call table address\n");
		return -EINVAL;
	}

	memset(siglog, 0, sizeof(siglog));

	if (!(orig_sys_kill = replace_system_call(__NR_kill, hooked_sys_kill))) {
		return -1;
	}

	proc_create("siglog", 0, NULL, &siglog_proc_fops);

	return 0;
}

static void __exit siglog_release(void) {
	remove_proc_entry("siglog", NULL);
	replace_system_call(__NR_kill, orig_sys_kill);
}

module_init(siglog_init);
module_exit(siglog_release);
