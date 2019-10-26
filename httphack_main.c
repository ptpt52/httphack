/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#define MODULE_NAME "httphack"
#define HTTPHACK_VERSION "5.0.0"

#define IPS_HTTPHACK_BYPASS_BIT 25
#define IPS_HTTPHACK_BYPASS (1 << IPS_HTTPHACK_BYPASS_BIT)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define skb_make_writable !skb_ensure_writable
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static inline int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	return nf_register_net_hooks(&init_net, reg, n);
}

static inline void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	nf_unregister_net_hooks(&init_net, reg, n);
}
#endif

#define HTTPHACK_println(fmt, ...) \
	do { \
		printk(KERN_DEFAULT "{" MODULE_NAME "}:%s(): " pr_fmt(fmt) "\n", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)

char http_url[1024] = "";

#define HTTP_RSP_FMT "" \
		"HTTP/1.1 301 Moved Permanently\r\n" \
		"Connection: close\r\n" \
		"Cache-Control: no-cache\r\n" \
		"Content-Type: text/html; charset=UTF-8\r\n" \
		"Location: %s\r\n" \
		"Content-Length: 0\r\n" \
		"\r\n"

char http_rsp[1024];
unsigned int http_rsp_len = 0;

static int httphack_major = 0;
static int httphack_minor = 0;
static int number_of_devices = 1;
static struct cdev httphack_cdev;
const char *httphack_dev_name = "httphack_ctl";
static struct class *httphack_class;
static struct device *httphack_dev;

static char httphack_ctl_buffer[PAGE_SIZE];
static void *httphack_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(httphack_ctl_buffer,
				sizeof(httphack_ctl_buffer) - 1,
				"# Usage:\n"
				"#    http_url=url -- set url to redirect\n"
				"#\n"
				"# Info:\n"
				"#    ...\n"
				"#\n"
				"# Reload cmd:\n"
				"\n"
				"http_url=%s\n"
				"\n",
				http_url);
		httphack_ctl_buffer[n] = 0;
		return httphack_ctl_buffer;
	}

	return NULL;
}

static void *httphack_next(struct seq_file *m, void *v, loff_t *pos)
{
	return NULL;
}

static void httphack_stop(struct seq_file *m, void *v)
{
}

static int httphack_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations httphack_seq_ops = {
	.start = httphack_start,
	.next = httphack_next,
	.stop = httphack_stop,
	.show = httphack_show,
};

static ssize_t httphack_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t httphack_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = 256;
	static char data[256];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <=256
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= 256) {
			HTTPHACK_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "http_url=", 9) == 0) {
		char *tmp = NULL;
		tmp = kmalloc(1024, GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;
		tmp[0] = 0;
		n = sscanf(data, "http_url=%s\n", tmp);
		tmp[1023] = 0;
		if (n == 1 && strlen(tmp) <= 512 && strlen(tmp) > 7) { // "http://..."
			strcpy(http_url, tmp);
			http_rsp_len = sprintf(http_rsp, HTTP_RSP_FMT, http_url);
			kfree(tmp);
			printk("%s", http_rsp);
			goto done;
		}
		http_url[0] = 0;
		http_rsp[0] = 0;
		http_rsp_len = 0;
		kfree(tmp);
	}

	HTTPHACK_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int httphack_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &httphack_seq_ops);
	if (ret)
		return ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	return 0;
}

static int httphack_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static struct file_operations httphack_fops = {
	.owner = THIS_MODULE,
	.open = httphack_open,
	.release = httphack_release,
	.read = httphack_read,
	.write = httphack_write,
	.llseek  = seq_lseek,
};

int skb_rcsum_tcpudp(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int len = ntohs(iph->tot_len);

	if (skb->len < len) {
		return -1;
	} else if (len < (iph->ihl * 4)) {
		return -1;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			tcph->check = 0;
			tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);
			skb->csum_start = (unsigned char *)tcph - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			skb->csum = 0;
			tcph->check = 0;
			skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
			tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			udph->check = 0;
			udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, 0);
			skb->csum_start = (unsigned char *)udph - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			if (udph->check) {
				skb->csum = 0;
				udph->check = 0;
				skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
				udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
				if (udph->check == 0)
					udph->check = CSUM_MANGLED_0;
			}
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	} else {
		return -1;
	}

	return 0;
}

#define TCPH(t) ((struct tcphdr *)(t))

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned httphack_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int httphack_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int httphack_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#else
static unsigned int httphack_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;

	if (http_rsp_len == 0) {
		//function disabled
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((IPS_HTTPHACK_BYPASS & ct->status)) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_REPLY) {
		return NF_ACCEPT;
	}

	l4 = (void *)iph + iph->ihl * 4;
	/* TODO match HTTP port 80 only ?
	if (TCPH(l4)->dest != __constant_htons(80)) {
		return NF_ACCEPT;
	}
	*/
	if (TCPH(l4)->syn) {
		return NF_ACCEPT;
	}
	if (skb->len - (iph->ihl * 4 + TCPH(l4)->doff * 4) <= 0) {
		//no data
		return NF_ACCEPT;
	}

	if (skb->len - (iph->ihl * 4 + TCPH(l4)->doff * 4) <= 12) { // HTTP/1.1 404 len
		//no enough data
		set_bit(IPS_HTTPHACK_BYPASS_BIT, &ct->status);
		return NF_ACCEPT;
	}

	if (!pskb_may_pull(skb, iph->ihl * 4 + TCPH(l4)->doff * 4 + 12)) {
		set_bit(IPS_HTTPHACK_BYPASS_BIT, &ct->status);
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if (strncasecmp("HTTP/", l4 + TCPH(l4)->doff * 4, 5) || *(unsigned int *)(l4 + TCPH(l4)->doff * 4 + 8) != *(const unsigned int *)" 404") {
		//not begin with "HTTP/... 404"
		set_bit(IPS_HTTPHACK_BYPASS_BIT, &ct->status);
		return NF_ACCEPT;
	}

	if (!skb_make_writable(skb, skb->len)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	do  {
		int data_len = skb->len - (iph->ihl * 4 + TCPH(l4)->doff * 4);
		if (data_len < http_rsp_len) {
			if (pskb_expand_head(skb, 0, http_rsp_len - data_len, GFP_ATOMIC)) {
				//expand fail
				return NF_ACCEPT;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;

			iph->tot_len = htons(ntohs(iph->tot_len) + http_rsp_len - data_len);
			skb->len += http_rsp_len - data_len;
			skb->tail += http_rsp_len - data_len;
		}

		memcpy(l4 + TCPH(l4)->doff * 4, http_rsp, http_rsp_len);

		TCPH(l4)->fin = 1; //close
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_rcsum_tcpudp(skb);
	} while (0);

	return NF_ACCEPT;
}

static struct nf_hook_ops httphack_hooks[] = {
	{    
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = httphack_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST + 8,
	},
};

static int __init httphack_init(void) {
	int retval = 0;
	dev_t devno;

	HTTPHACK_println("version: " HTTPHACK_VERSION "");

	if (httphack_major>0) {
		devno = MKDEV(httphack_major, httphack_minor);
		retval = register_chrdev_region(devno, number_of_devices, httphack_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, httphack_minor, number_of_devices, httphack_dev_name);
	}
	if (retval < 0) {
		HTTPHACK_println("alloc_chrdev_region failed!");
		return retval;
	}
	httphack_major = MAJOR(devno);
	httphack_minor = MINOR(devno);
	HTTPHACK_println("httphack_major=%d, httphack_minor=%d", httphack_major, httphack_minor);

	cdev_init(&httphack_cdev, &httphack_fops);
	httphack_cdev.owner = THIS_MODULE;
	httphack_cdev.ops = &httphack_fops;

	retval = cdev_add(&httphack_cdev, devno, 1);
	if (retval) {
		HTTPHACK_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

	httphack_class = class_create(THIS_MODULE,"httphack_class");
	if (IS_ERR(httphack_class)) {
		HTTPHACK_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	httphack_dev = device_create(httphack_class, NULL, devno, NULL, httphack_dev_name);
	if (!httphack_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	http_rsp[0] = 0;

	retval = nf_register_hooks(httphack_hooks, ARRAY_SIZE(httphack_hooks));
	if (retval) {
		goto err0;
	}

	return 0;

	//nf_unregister_hooks(httphack_hooks, ARRAY_SIZE(httphack_hooks));
err0:
	device_destroy(httphack_class, devno);
device_create_failed:
	class_destroy(httphack_class);
class_create_failed:
	cdev_del(&httphack_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);

	return retval;
}

static void __exit httphack_exit(void) {
	dev_t devno;

	HTTPHACK_println("removing");

	nf_unregister_hooks(httphack_hooks, ARRAY_SIZE(httphack_hooks));

	devno = MKDEV(httphack_major, httphack_minor);
	device_destroy(httphack_class, devno);
	class_destroy(httphack_class);
	cdev_del(&httphack_cdev);
	unregister_chrdev_region(devno, number_of_devices);
	HTTPHACK_println("done");
	return;
}

module_init(httphack_init);
module_exit(httphack_exit);

MODULE_AUTHOR("Q2hlbiBNaW5xaWFuZyA8cHRwdDUyQGdtYWlsLmNvbT4=");
MODULE_VERSION(HTTPHACK_VERSION);
MODULE_DESCRIPTION("HTTP 404 redirect hack");
MODULE_LICENSE("GPL");
