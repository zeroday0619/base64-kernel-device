#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#define MAX_INPUT_LEN   4096
#define MAX_OUTPUT_LEN  8192

struct base64_device {
        struct mutex lock;
        char inbuf[MAX_INPUT_LEN];
        size_t in_len;
        char outbuf[MAX_OUTPUT_LEN];
        size_t out_len;
};

struct xor_device {
        struct mutex lock;
        char inbuf[MAX_INPUT_LEN];
        size_t in_len;
        char outbuf[MAX_INPUT_LEN];
        size_t out_len;
};

static struct base64_device enc_dev;
static struct base64_device dec_dev;
static struct xor_device xorenc_dev;
static struct xor_device xordec_dev;

static unsigned char xor_key = 0xAA;
module_param(xor_key, byte, 0644);

static const char b64_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_char_value(char c)
{
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        if (c == '=') return -2;
        return -1;
}

static size_t base64_encode_k(const unsigned char *src, size_t len,
                              char *dst, size_t dst_size)
{
        size_t i = 0, j = 0;
        if (!src || !dst) return 0;
        if (dst_size < (4 * ((len + 2) / 3) + 1)) return 0;

        while (i < len) {
                size_t rem = len - i;
                unsigned int a = src[i++];
                unsigned int b = rem > 1 ? src[i++] : 0;
                unsigned int c = rem > 2 ? src[i++] : 0;
                unsigned int t = (a << 16) | (b << 8) | c;
                dst[j++] = b64_table[(t >> 18) & 0x3F];
                dst[j++] = b64_table[(t >> 12) & 0x3F];
                dst[j++] = rem > 1 ? b64_table[(t >> 6) & 0x3F] : '=';
                dst[j++] = rem > 2 ? b64_table[t & 0x3F] : '=';
        }
        dst[j] = 0;
        return j;
}

static ssize_t base64_decode_k(const char *src, size_t len,
                               unsigned char *dst, size_t dst_size)
{
        size_t i = 0, j = 0;
        if (len % 4 != 0) return -EINVAL;

        while (i < len) {
                int v0 = b64_char_value(src[i++]);
                int v1 = b64_char_value(src[i++]);
                int v2 = b64_char_value(src[i++]);
                int v3 = b64_char_value(src[i++]);
                if (v0 < 0 || v1 < 0 || v2 < -2 || v3 < -2) return -EINVAL;

                if (v2 == -2 && v3 == -2) {
                        unsigned int t = (v0 << 18) | (v1 << 12);
                        if (j + 1 > dst_size) return -ENOSPC;
                        dst[j++] = (t >> 16) & 0xFF;
                        break;
                } else if (v3 == -2) {
                        unsigned int t;
                        if (v2 < 0) return -EINVAL;
                        t = (v0 << 18) | (v1 << 12) | (v2 << 6);
                        if (j + 2 > dst_size) return -ENOSPC;
                        dst[j++] = (t >> 16) & 0xFF;
                        dst[j++] = (t >> 8) & 0xFF;
                        break;
                } else {
                        unsigned int t;
                        if (v2 < 0 || v3 < 0) return -EINVAL;
                        t = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
                        if (j + 3 > dst_size) return -ENOSPC;
                        dst[j++] = (t >> 16) & 0xFF;
                        dst[j++] = (t >> 8) & 0xFF;
                        dst[j++] = t & 0xFF;
                }
        }
        return j;
}

static ssize_t base64enc_write(struct file *file,
                               const char __user *buf,
                               size_t count, loff_t *ppos)
{
        ssize_t ret;
        size_t n;

        mutex_lock(&enc_dev.lock);

        n = count > MAX_INPUT_LEN ? MAX_INPUT_LEN : count;

        if (copy_from_user(enc_dev.inbuf, buf, n)) {
            pr_err("base64enc: copy_from_user failed\n");
            ret = -EFAULT;
            goto out;
        }

        enc_dev.in_len = n;
        enc_dev.out_len = base64_encode_k(
                (unsigned char *)enc_dev.inbuf, n,
                enc_dev.outbuf, MAX_OUTPUT_LEN);

        if (!enc_dev.out_len) {
            pr_err("base64enc: encode failed\n");
            ret = -EINVAL;
            goto out;
        }

        pr_info("base64enc: encoded %zu bytes -> %zu bytes\n",
                n, enc_dev.out_len);

        *ppos += n;
        ret = n;

out:
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
                goto out;
        }

        if (count > enc_dev.out_len - *ppos)
                count = enc_dev.out_len - *ppos;

        if (copy_to_user(buf, enc_dev.outbuf + *ppos, count)) {
                pr_err("base64enc: copy_to_user failed\n");
                ret = -EFAULT;
                goto out;
        }

        pr_info("base64enc: read %zu bytes\n", count);

        *ppos += count;
        ret = count;

out:
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
        size_t n;
        ssize_t dec_len;

        mutex_lock(&dec_dev.lock);

        n = count > MAX_INPUT_LEN ? MAX_INPUT_LEN : count;

        if (copy_from_user(dec_dev.inbuf, buf, n)) {
                pr_err("base64dec: copy_from_user failed\n");
                ret = -EFAULT;
                goto out;
        }

        dec_len = base64_decode_k(dec_dev.inbuf, n,
                                  (unsigned char *)dec_dev.outbuf,
                                  MAX_OUTPUT_LEN);

        if (dec_len < 0) {
                pr_err("base64dec: decode error %zd\n", dec_len);
                ret = dec_len;
                goto out;
        }

        dec_dev.out_len = dec_len;

        pr_info("base64dec: decoded %zu bytes -> %zu bytes\n",
                n, dec_len);

        *ppos += n;
        ret = n;

out:
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
                goto out;
        }

        if (count > dec_dev.out_len - *ppos)
                count = dec_dev.out_len - *ppos;

        if (copy_to_user(buf, dec_dev.outbuf + *ppos, count)) {
                pr_err("base64dec: copy_to_user failed\n");
                ret = -EFAULT;
                goto out;
        }

        pr_info("base64dec: read %zu bytes\n", count);

        *ppos += count;
        ret = count;

out:
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

static ssize_t xorenc_write(struct file *file,
                            const char __user *buf,
                            size_t count, loff_t *ppos)
{
        size_t n, i;
        ssize_t ret;

        mutex_lock(&xorenc_dev.lock);

        n = count > MAX_INPUT_LEN ? MAX_INPUT_LEN : count;

        if (copy_from_user(xorenc_dev.inbuf, buf, n)) {
                pr_err("xorenc: copy_from_user failed\n");
                ret = -EFAULT;
                goto out;
        }

        xorenc_dev.in_len = n;

        for (i = 0; i < n; i++)
                xorenc_dev.outbuf[i] = xorenc_dev.inbuf[i] ^ xor_key;

        xorenc_dev.out_len = n;

        pr_info("xorenc: processed %zu bytes (key=0x%02X)\n", n, xor_key);

        *ppos += n;
        ret = n;

out:
        mutex_unlock(&xorenc_dev.lock);
        return ret;
}

static ssize_t xorenc_read(struct file *file,
                           char __user *buf,
                           size_t count, loff_t *ppos)
{
        ssize_t ret;

        mutex_lock(&xorenc_dev.lock);

        if (*ppos >= xorenc_dev.out_len) {
                ret = 0;
                goto out;
        }

        if (count > xorenc_dev.out_len - *ppos)
                count = xorenc_dev.out_len - *ppos;

        if (copy_to_user(buf, xorenc_dev.outbuf + *ppos, count)) {
                pr_err("xorenc: copy_to_user failed\n");
                ret = -EFAULT;
                goto out;
        }

        pr_info("xorenc: read %zu bytes\n", count);

        *ppos += count;
        ret = count;

out:
        mutex_unlock(&xorenc_dev.lock);
        return ret;
}

static const struct file_operations xorenc_fops = {
        .owner  = THIS_MODULE,
        .read   = xorenc_read,
        .write  = xorenc_write,
        .llseek = noop_llseek,
};

static struct miscdevice xorenc_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name  = "xorenc",
        .fops  = &xorenc_fops,
        .mode  = 0666,
};

static ssize_t xordec_write(struct file *file,
                            const char __user *buf,
                            size_t count, loff_t *ppos)
{
        size_t n, i;
        ssize_t ret;

        mutex_lock(&xordec_dev.lock);

        n = count > MAX_INPUT_LEN ? MAX_INPUT_LEN : count;

        if (copy_from_user(xordec_dev.inbuf, buf, n)) {
                pr_err("xordec: copy_from_user failed\n");
                ret = -EFAULT;
                goto out;
        }

        xordec_dev.in_len = n;

        for (i = 0; i < n; i++)
                xordec_dev.outbuf[i] = xordec_dev.inbuf[i] ^ xor_key;

        xordec_dev.out_len = n;

        pr_info("xordec: processed %zu bytes (key=0x%02X)\n", n, xor_key);

        *ppos += n;
        ret = n;

out:
        mutex_unlock(&xordec_dev.lock);
        return ret;
}

static ssize_t xordec_read(struct file *file,
                           char __user *buf,
                           size_t count, loff_t *ppos)
{
        ssize_t ret;

        mutex_lock(&xordec_dev.lock);

        if (*ppos >= xordec_dev.out_len) {
                ret = 0;
                goto out;
        }

        if (count > xordec_dev.out_len - *ppos)
                count = xordec_dev.out_len - *ppos;

        if (copy_to_user(buf, xordec_dev.outbuf + *ppos, count)) {
                pr_err("xordec: copy_to_user failed\n");
                ret = -EFAULT;
                goto out;
        }

        pr_info("xordec: read %zu bytes\n", count);

        *ppos += count;
        ret = count;

out:
        mutex_unlock(&xordec_dev.lock);
        return ret;
}

static const struct file_operations xordec_fops = {
        .owner  = THIS_MODULE,
        .read   = xordec_read,
        .write  = xordec_write,
        .llseek = noop_llseek,
};

static struct miscdevice xordec_miscdev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name  = "xordec",
        .fops  = &xordec_fops,
        .mode  = 0666,
};

static int __init base64dev_init(void)
{
        int ret;

        pr_info("base64dev: init (xor_key=0x%02X)\n", xor_key);

        mutex_init(&enc_dev.lock);
        mutex_init(&dec_dev.lock);
        mutex_init(&xorenc_dev.lock);
        mutex_init(&xordec_dev.lock);

        ret = misc_register(&base64enc_miscdev);
        if (ret) {
                pr_err("base64dev: failed to register /dev/base64enc\n");
                return ret;
        }

        ret = misc_register(&base64dec_miscdev);
        if (ret) {
                pr_err("base64dev: failed to register /dev/base64dec\n");
                misc_deregister(&base64enc_miscdev);
                return ret;
        }

        ret = misc_register(&xorenc_miscdev);
        if (ret) {
                pr_err("base64dev: failed to register /dev/xorenc\n");
                misc_deregister(&base64dec_miscdev);
                misc_deregister(&base64enc_miscdev);
                return ret;
        }

        ret = misc_register(&xordec_miscdev);
        if (ret) {
                pr_err("base64dev: failed to register /dev/xordec\n");
                misc_deregister(&xorenc_miscdev);
                misc_deregister(&base64dec_miscdev);
                misc_deregister(&base64enc_miscdev);
                return ret;
        }

        pr_info("base64dev: loaded successfully\n");
        return 0;
}

static void __exit base64dev_exit(void)
{
        misc_deregister(&xordec_miscdev);
        misc_deregister(&xorenc_miscdev);
        misc_deregister(&base64dec_miscdev);
        misc_deregister(&base64enc_miscdev);
        pr_info("base64dev: unloaded\n");
}

module_init(base64dev_init);
module_exit(base64dev_exit);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Euiseo Cha <euiseo.cha@gmail.com>");
MODULE_DESCRIPTION("base64 encode/decode + xorenc/xordec");
MODULE_VERSION("0.4");
