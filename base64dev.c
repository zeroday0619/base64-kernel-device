#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#define DRIVER_NAME "base64dev"
#define MAX_INPUT_LEN   4096
#define MAX_OUTPUT_LEN  8192

struct base64_device {
        struct mutex lock;
        char inbuf[MAX_INPUT_LEN];
        size_t in_len;
        char outbuf[MAX_OUTPUT_LEN];
        size_t out_len;
};

static struct base64_device enc_dev;
static struct base64_device dec_dev;

static const char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_char_value(char c)
{
        if (c >= 'A' && c <= 'Z')
                return c - 'A';
        if (c >= 'a' && c <= 'z')
                return c - 'a' + 26;
        if (c >= '0' && c <= '9')
                return c - '0' + 52;
        if (c == '+')
                return 62;
        if (c == '/')
                return 63;
        if (c == '=')
                return -2;
        return -1;
}

static size_t base64_encode_k(const unsigned char *src, size_t len,
                              char *dst, size_t dst_size)
{
        size_t i = 0, j = 0;
        if (!src || !dst)
                return 0;
        if (dst_size < (4 * ((len + 2) / 3) + 1))
                return 0;

        while (i < len) {
                size_t rem = len - i;
                unsigned int octet_a = src[i++];
                unsigned int octet_b = rem > 1 ? src[i++] : 0;
                unsigned int octet_c = rem > 2 ? src[i++] : 0;
                unsigned int triple = (octet_a << 16) |
                                      (octet_b << 8) |
                                      octet_c;

                dst[j++] = b64_table[(triple >> 18) & 0x3F];
                dst[j++] = b64_table[(triple >> 12) & 0x3F];
                if (rem > 1)
                        dst[j++] = b64_table[(triple >> 6) & 0x3F];
                else
                        dst[j++] = '=';
                if (rem > 2)
                        dst[j++] = b64_table[triple & 0x3F];
                else
                        dst[j++] = '=';
        }

        dst[j] = '\0';
        return j;
}

static ssize_t base64_decode_k(const char *src, size_t len,
                               unsigned char *dst, size_t dst_size)
{
        size_t i = 0, j = 0;
        if (!src || !dst)
                return -EINVAL;
        if (len % 4 != 0)
                return -EINVAL;

        while (i < len) {
            int v0, v1, v2, v3;
            char c0 = src[i++];
            char c1 = src[i++];
            char c2 = src[i++];
            char c3 = src[i++];
            v0 = b64_char_value(c0);
            v1 = b64_char_value(c1);
            v2 = b64_char_value(c2);
            v3 = b64_char_value(c3);
            if (v0 < 0 || v1 < 0 || v2 < -2 || v3 < -2)
                    return -EINVAL;

            if (v2 == -2 && v3 == -2) {
                    unsigned int triple = (v0 << 18) | (v1 << 12);
                    if (j + 1 > dst_size)
                            return -ENOSPC;
                    dst[j++] = (triple >> 16) & 0xFF;
                    break;
            } else if (v3 == -2) {
                    if (v2 < 0)
                            return -EINVAL;
                    unsigned int triple = (v0 << 18) |
                                          (v1 << 12) |
                                          (v2 << 6);
                    if (j + 2 > dst_size)
                            return -ENOSPC;
                    dst[j++] = (triple >> 16) & 0xFF;
                    dst[j++] = (triple >> 8) & 0xFF;
                    break;
            } else {
                    if (v2 < 0 || v3 < 0)
                            return -EINVAL;
                    unsigned int triple = (v0 << 18) |
                                          (v1 << 12) |
                                          (v2 << 6)  |
                                          v3;
                    if (j + 3 > dst_size)
                            return -ENOSPC;
                    dst[j++] = (triple >> 16) & 0xFF;
                    dst[j++] = (triple >> 8) & 0xFF;
                    dst[j++] = triple & 0xFF;
            }
        }
        return j;
}

static ssize_t base64enc_write(struct file *file,
                               const char __user *buf,
                               size_t count, loff_t *ppos)
{
        ssize_t ret;
        size_t to_copy;
        if (count == 0)
                return 0;

        mutex_lock(&enc_dev.lock);

        if (count > MAX_INPUT_LEN)
                to_copy = MAX_INPUT_LEN;
        else
                to_copy = count;

        if (copy_from_user(enc_dev.inbuf, buf, to_copy)) {
                ret = -EFAULT;
                goto out_unlock;
        }

        enc_dev.in_len = to_copy;
        enc_dev.out_len = base64_encode_k(
                (const unsigned char *)enc_dev.inbuf,
                enc_dev.in_len,
                enc_dev.outbuf,
                MAX_OUTPUT_LEN
        );

        if (enc_dev.out_len == 0) {
                ret = -EINVAL;
                goto out_unlock;
        }

        *ppos += to_copy;
        ret = to_copy;

out_unlock:
        mutex_unlock(&enc_dev.lock);
        return ret;
}

static ssize_t base64enc_read(struct file *file,
                              char __user *buf,
                              size_t count, loff_t *ppos)
{
        ssize_t ret;
        mutex_lock(&enc_dev.lock);

        if (*ppos >= enc_dev.out_len) {
                ret = 0;
                goto out_unlock;
        }

        if (count > enc_dev.out_len - *ppos)
                count = enc_dev.out_len - *ppos;

        if (copy_to_user(buf, enc_dev.outbuf + *ppos, count)) {
                ret = -EFAULT;
                goto out_unlock;
        }

        *ppos += count;
        ret = count;

out_unlock:
        mutex_unlock(&enc_dev.lock);
        return ret;
}

static const struct file_operations base64enc_fops = {
        .owner  = THIS_MODULE,
        .read   = base64enc_read,
        .write  = base64enc_write,
        .llseek = noop_llseek,
};

static struct miscdevice base64enc_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name  = "base64enc",
        .fops  = &base64enc_fops,
        .mode  = 0666,
};

static ssize_t base64dec_write(struct file *file,
                               const char __user *buf,
                               size_t count, loff_t *ppos)
{
        ssize_t ret;
        size_t to_copy;
        ssize_t dec_len;

        if (count == 0)
                return 0;

        mutex_lock(&dec_dev.lock);

        if (count > MAX_INPUT_LEN)
                to_copy = MAX_INPUT_LEN;
        else
                to_copy = count;

        if (copy_from_user(dec_dev.inbuf, buf, to_copy)) {
                ret = -EFAULT;
                goto out_unlock;
        }

        dec_dev.in_len = to_copy;

        dec_len = base64_decode_k(
                dec_dev.inbuf,
                dec_dev.in_len,
                (unsigned char *)dec_dev.outbuf,
                MAX_OUTPUT_LEN
        );

        if (dec_len < 0) {
                ret = dec_len;
                goto out_unlock;
        }

        dec_dev.out_len = dec_len;

        *ppos += to_copy;
        ret = to_copy;

out_unlock:
        mutex_unlock(&dec_dev.lock);
        return ret;
}

static ssize_t base64dec_read(struct file *file,
                              char __user *buf,
                              size_t count, loff_t *ppos)
{
        ssize_t ret;
        mutex_lock(&dec_dev.lock);

        if (*ppos >= dec_dev.out_len) {
                ret = 0;
                goto out_unlock;
        }

        if (count > dec_dev.out_len - *ppos)
                count = dec_dev.out_len - *ppos;

        if (copy_to_user(buf, dec_dev.outbuf + *ppos, count)) {
                ret = -EFAULT;
                goto out_unlock;
        }

        *ppos += count;
        ret = count;

out_unlock:
        mutex_unlock(&dec_dev.lock);
        return ret;
}

static const struct file_operations base64dec_fops = {
        .owner  = THIS_MODULE,
        .read   = base64dec_read,
        .write  = base64dec_write,
        .llseek = noop_llseek,
};

static struct miscdevice base64dec_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name  = "base64dec",
        .fops  = &base64dec_fops,
        .mode  = 0666,
};

static int __init base64dev_init(void)
{
        int ret;
        mutex_init(&enc_dev.lock);
        mutex_init(&dec_dev.lock);

        ret = misc_register(&base64enc_miscdev);
        if (ret) {
		pr_err(DRIVER_NAME ": failed to register /dev/base64enc (%d)\n", ret);
                return ret;
	}

        ret = misc_register(&base64dec_miscdev);
        if (ret) {
		pr_err(DRIVER_NAME ": failed to register /dev/base64dec (%d)\n", ret);
                misc_deregister(&base64enc_miscdev);
                return ret;
        }
	pr_info(DRIVER_NAME ": loaded. /dev/base64enc, /dev/base64dec ready\n");
        return 0;
}

static void __exit base64dev_exit(void)
{
        misc_deregister(&base64dec_miscdev);
        misc_deregister(&base64enc_miscdev);
}

module_init(base64dev_init);
module_exit(base64dev_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Euiseo Cha <euiseo.cha@gmail.com>");
MODULE_DESCRIPTION("base64 encode/decode device");
MODULE_VERSION("0.1");
