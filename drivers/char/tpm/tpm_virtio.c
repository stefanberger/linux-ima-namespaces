// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 IBM Corporation
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 *
 * Maintained by: <tpmdd-devel@lists.sourceforge.net>
 *
 * Device driver for vTPM (vTPM proxy driver)
 */

#include <linux/module.h>
#include <linux/pm.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/tpm.h>
#include <linux/virtio_tpm.h>
#include <linux/virtio_ids.h>

#include "tpm.h"

#define VIRTIO_REQ_COMPLETE_FLAG  BIT(0)

struct virtio_dev
{
	struct tpm_chip *chip;
	struct virtqueue *vq;
	struct scatterlist sg[4];
	struct virtio_tpm_cmd_header hdr;
	struct virtio_tpm_cmd_result result;

	/* TPM buffersize and receive buffer */
	u16 buffersize;
	unsigned char *buffer;

	struct mutex lock;
	/* whether need to call virtqueue_get_buf; protected by lock */
	bool need_get_buf;
	/* whether response has been received; protected by lock */
	bool response_received;
};

static int virtio_tpm_op_send(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct virtio_dev *virtio_dev = dev_get_drvdata(&chip->dev);
	struct scatterlist *sgs[4];
	unsigned int i;
	int len, err;

	//printk(KERN_INFO "%s @ %u  virtio_dev=%px\n", __func__, __LINE__, virtio_dev);

	/* header */
	sg_init_one(&virtio_dev->sg[0], &virtio_dev->hdr, sizeof(virtio_dev->hdr));
	/* send buffer */
	sg_init_one(&virtio_dev->sg[1], buf, count);
	/* recv buffer */
	sg_init_one(&virtio_dev->sg[2], virtio_dev->buffer, virtio_dev->buffersize);
	/* result */
	virtio_dev->result.status = 0xff;
	sg_init_one(&virtio_dev->sg[3], &virtio_dev->result,
	                                sizeof(virtio_dev->result));

	for (i = 0; i < 4; i++)
		sgs[i] = &virtio_dev->sg[i];

	mutex_lock(&virtio_dev->lock);

	if (virtio_dev->need_get_buf)
		virtqueue_get_buf(virtio_dev->vq, &len);

	err = virtqueue_add_sgs(virtio_dev->vq, sgs, 2, 2,
	                        virtio_dev, GFP_ATOMIC);
	if (err)
		goto err_unlock;
	virtio_dev->need_get_buf = true;
	virtio_dev->response_received = false;

	mutex_unlock(&virtio_dev->lock);

	virtqueue_kick(virtio_dev->vq);

	return 0;

err_unlock:
	mutex_unlock(&virtio_dev->lock);
	printk(KERN_INFO "cannot send: %d\n", err);

	return err;
}

/* Callback for when response has been received */
static void virtio_notify_response_received(struct virtqueue *vq)
{
	struct virtio_dev *virtio_dev = vq->vdev->priv;
	unsigned int len;

#if 0
	printk(KERN_INFO "%s @ %u  virtio_dev=%px  virtio_device=%px\n",
	        __func__, __LINE__, virtio_dev, vq->vdev);
#endif

	virtqueue_get_buf(vq, &len);

	mutex_lock(&virtio_dev->lock);

	virtio_dev->need_get_buf = false;
	virtio_dev->response_received = true;

	mutex_unlock(&virtio_dev->lock);
}

static int virtio_tpm_op_recv(struct tpm_chip *chip, u8 *buf, size_t count)
{
	struct virtio_dev *virtio_dev = dev_get_drvdata(&chip->dev);
	struct tpm_header *header = (struct tpm_header *)virtio_dev->buffer;
	int tocopy;

	if (virtio_dev->result.status != 0)
		return -EBADMSG;

	tocopy = min(count, virtio_dev->buffersize);
	tocopy = min(tocopy, be32_to_cpu(header->length));
	memcpy(buf, virtio_dev->buffer, tocopy);

#if 0
	printk(KERN_INFO "%s @ %u  virtio_dev=%px\n", __func__, __LINE__, virtio_dev);
	printk(KERN_INFO "%02x %02x %02x %02x %02x %02x   len=%d buf=%px status=%d\n",
	       buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], tocopy, buf,
	       virtio_dev->result.status);
#endif
	return tocopy;
}

static void virtio_tpm_op_cancel(struct tpm_chip *chip)
{
	struct virtio_dev *virtio_dev = dev_get_drvdata(&chip->dev);
	int len;

	mutex_lock(&virtio_dev->lock);

	if (virtio_dev->need_get_buf) {
		virtqueue_get_buf(virtio_dev->vq, &len);
		virtio_dev->need_get_buf = false;
	}

	mutex_unlock(&virtio_dev->lock);
}

static u8 virtio_tpm_op_status(struct tpm_chip *chip)
{
	struct virtio_dev *virtio_dev = dev_get_drvdata(&chip->dev);
	int ret = 0;

	mutex_lock(&virtio_dev->lock);

	if (virtio_dev->response_received)
		ret = VIRTIO_REQ_COMPLETE_FLAG;

	mutex_unlock(&virtio_dev->lock);

	return ret;
}

static int virtio_request_locality(struct tpm_chip *chip, int loc)
{
	struct virtio_dev *virtio_dev = dev_get_drvdata(&chip->dev);

	virtio_dev->hdr.locty = loc;

	return 0;
}

static const struct tpm_class_ops tpm_crb = {
	.flags = TPM_OPS_AUTO_STARTUP,
	.recv = virtio_tpm_op_recv,
	.send = virtio_tpm_op_send,
	.status = virtio_tpm_op_status,
	.cancel = virtio_tpm_op_cancel,
	.request_locality = virtio_request_locality,
	.req_complete_mask = VIRTIO_REQ_COMPLETE_FLAG,
	.req_complete_val = VIRTIO_REQ_COMPLETE_FLAG,
};

static int virtio_tpm_init_vqs(struct virtio_device *vdev)
{
	struct virtio_dev *virtio_dev = vdev->priv;
	struct virtqueue_info vqs_info[] = {
		{ "transfer", virtio_notify_response_received },
	};
	struct virtqueue *vqs[1];
	int err;

	err = virtio_find_vqs(vdev, 1, vqs, vqs_info, NULL);
	if (err)
		return err;

	virtio_dev->vq = vqs[0];

	virtio_device_ready(vdev);

	return 0;
}

static int virtio_tpm_probe(struct virtio_device *vdev)
{
	struct virtio_dev *virtio_dev;
	struct tpm_chip *chip;
	__u8 tpm_version;
	int err;

	printk(KERN_INFO "ooo PROBE!  virtio_device=%px\n", vdev);
	virtio_dev = devm_kzalloc(&vdev->dev, sizeof(*virtio_dev), GFP_KERNEL);
	if (virtio_dev == NULL)
		return -ENOMEM;
	vdev->priv = virtio_dev;

	printk(KERN_INFO "%s @ %u  virtio_dev=%px\n", __func__, __LINE__, virtio_dev);
	chip = tpmm_chip_alloc(&vdev->dev, &tpm_crb);
	if (IS_ERR(chip)) {
		err = PTR_ERR(chip);
		return err;
	}
	dev_set_drvdata(&chip->dev, virtio_dev);

	err = virtio_tpm_init_vqs(vdev);
	if (err)
		return err;

	virtio_cread(vdev, struct virtio_tpm_config,
	             buffersize, &virtio_dev->buffersize);
	if (virtio_dev->buffersize < TPM_BUFSIZE)
		virtio_dev->buffersize = TPM_BUFSIZE;
	virtio_dev->buffer = kmalloc(virtio_dev->buffersize, GFP_KERNEL);
	if (!virtio_dev->buffer) {
		err = -ENOMEM;
		goto err_del_vqs;
	}

	virtio_cread(vdev, struct virtio_tpm_config,
	             tpm_version, &tpm_version);
	if (tpm_version == 2)
		chip->flags |= TPM_CHIP_FLAG_TPM2;

	err = tpm_chip_register(chip);
	if (err)
		goto err_del_vqs;

	virtio_dev->chip = chip;
	mutex_init(&virtio_dev->lock);

	return 0;

err_del_vqs:
	vdev->config->del_vqs(vdev);
	return err;
}

static void virtio_tpm_remove(struct virtio_device *vdev)
{
	struct virtio_dev *virtio_dev = vdev->priv;

	virtio_tpm_op_cancel(virtio_dev->chip);
	tpm_chip_unregister(virtio_dev->chip);
	virtio_reset_device(vdev);
	vdev->config->del_vqs(vdev);
	kfree(virtio_dev->buffer);
}

#ifdef CONFIG_PM_SLEEP
static int virtio_tpm_freeze(struct virtio_device *vdev)
{
	struct tpm_chip *chip = dev_get_drvdata(&vdev->dev);
	printk(KERN_INFO "ooo PM freeze  chip=%px\n", chip);
	if (!(chip->flags & TPM_CHIP_FLAG_SUSPENDED))
		tpm_pm_suspend(&vdev->dev);
	vdev->config->del_vqs(vdev);

	return 0;
}

static int virtio_tpm_restore(struct virtio_device *vdev)
{
	int err;
	printk(KERN_INFO "ooo PM restore\n");
	err = virtio_tpm_init_vqs(vdev);
	if (err)
		return err;
	return tpm_pm_resume_state(&vdev->dev);
}
#endif

static unsigned int features[] = {
	/* none */
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_TPM, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_tpm_driver = {
	.driver.name = KBUILD_MODNAME,
	.feature_table       = features,
	.feature_table_size  = ARRAY_SIZE(features),
	.id_table            = id_table,
	.probe               = virtio_tpm_probe,
	.remove              = virtio_tpm_remove,
#ifdef CONFIG_PM_SLEEP
	.freeze	             = virtio_tpm_freeze,
	.restore             = virtio_tpm_restore,
#endif
};

static int __init virtio_module_init(void)
{
	return register_virtio_driver(&virtio_tpm_driver);
}

static void __exit virtio_module_exit(void)
{
	printk(KERN_INFO "UNREGISTERING\n");
	unregister_virtio_driver(&virtio_tpm_driver);
}

module_init(virtio_module_init);
module_exit(virtio_module_exit);

MODULE_DESCRIPTION("Virtio TPM Driver");
MODULE_LICENSE("GPL");
