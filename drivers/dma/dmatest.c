/*
 * DMA Engine test module
 *
 * Copyright (C) 2007 Atmel Corporation
 * Copyright (C) 2013 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define DEBUG

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <asm/cacheflush.h>

/**
 * struct dmatest_info - test information.
 * @lock:		access protection to the fields of this structure
 */
static struct dmatest_info {
	/* Internal state */
	struct list_head	channels;
	unsigned int		nr_channels;
	struct mutex		lock;
} test_info = {
	.channels = LIST_HEAD_INIT(test_info.channels),
	.lock = __MUTEX_INITIALIZER(test_info.lock),
};

enum dmatest_buf_type {
	BUF_SRC = 0,
	BUF_DST = 1,
};

#define SRC_COUNT		(4)
#define DST_COUNT		(9 + 4)

struct dmatest_thread {
	struct list_head	node;
	struct task_struct	*task;
	struct dma_chan		*chan;
	u8			*srcs[SRC_COUNT];
	u8			*dsts[DST_COUNT];
	dma_addr_t		src_dmas[SRC_COUNT];
	dma_addr_t		dst_dmas[DST_COUNT];
	bool			done;
};

struct dmatest_chan {
	struct list_head	node;
	struct dma_chan		*chan;
	struct list_head	threads;
};

static DECLARE_WAIT_QUEUE_HEAD(thread_wait);

static void dmatest_verify(struct dmatest_thread *thread, unsigned int index,
			   u8 expected, bool print_success)
{
	u8 *buf = thread->dsts[index];
	unsigned int i;

	/* Definitely overkill, but just to be safe. */
	flush_cache_all();

	for (i = 0; i < PAGE_SIZE; ++i) {
		if (buf[i] != expected) {
			pr_info("%s: dst[%u] mismatch @%u: got %u expected %u\n",
				__func__, index, i, buf[i], expected);
			return;
		}
	}

	if (print_success)
		pr_info("%s: dst[%u] verified, contains %u\n", __func__,
			index, expected);
}

/* poor man's completion - we want to use wait_event_freezable() on it */
struct dmatest_done {
	bool			done;
	wait_queue_head_t	*wait;
};

static void dmatest_callback(void *arg)
{
	struct dmatest_done *done = arg;

	done->done = true;
	wake_up_all(done->wait);
}

static void result(const char *err, unsigned long data)
{
	pr_info("%s: result: '%s' (%lu)\n", current->comm, err, data);
}

static int dmatest_map_src(struct dmatest_thread *thread, unsigned int index)
{
	struct device *dev = thread->chan->device->dev;
	void *buf = thread->srcs[index];
	struct page *pg = virt_to_page(buf);
	int ret;

	thread->src_dmas[index] = dma_map_page(dev, pg, 0, PAGE_SIZE,
					       DMA_TO_DEVICE);
	ret = dma_mapping_error(dev, thread->src_dmas[index]);
	if (ret) {
		result("src mapping error", ret);
		return ret;
	}

	return 0;
}

static void dmatest_unmap_src(struct dmatest_thread *thread, unsigned int index)
{
	struct device *dev = thread->chan->device->dev;

	if (dma_mapping_error(dev, thread->src_dmas[index]))
		return;

	dma_unmap_page(dev, thread->src_dmas[index], PAGE_SIZE, DMA_TO_DEVICE);
	thread->src_dmas[index] = DMA_ERROR_CODE;
}

static int dmatest_map_dst(struct dmatest_thread *thread, unsigned int index)
{
	struct device *dev = thread->chan->device->dev;
	void *buf = thread->dsts[index];
	struct page *pg = virt_to_page(buf);
	int ret;

	thread->dst_dmas[index] = dma_map_page(dev, pg, 0, PAGE_SIZE,
					       DMA_BIDIRECTIONAL);
	ret = dma_mapping_error(dev, thread->dst_dmas[index]);
	if (ret) {
		result("dst mapping error", ret);
		return ret;
	}

	return 0;
}

static void dmatest_unmap_dst(struct dmatest_thread *thread, unsigned int index)
{
	struct device *dev = thread->chan->device->dev;

	if (dma_mapping_error(dev, thread->dst_dmas[index]))
		return;

	dma_unmap_page(dev, thread->dst_dmas[index], PAGE_SIZE, DMA_BIDIRECTIONAL);
	thread->dst_dmas[index] = DMA_ERROR_CODE;
}

static int dmatest_map(struct dmatest_thread *thread,
		       enum dmatest_buf_type type, unsigned int index)
{
	if (type == BUF_SRC)
		return dmatest_map_src(thread, index);
	else
		return dmatest_map_dst(thread, index);
}

static void dmatest_unmap(struct dmatest_thread *thread,
			  enum dmatest_buf_type type, unsigned int index)
{
	if (type == BUF_SRC)
		dmatest_unmap_src(thread, index);
	else
		dmatest_unmap_dst(thread, index);
}

static int dmatest_alloc_buffers(struct dmatest_thread *thread)
{
	unsigned int i;

	for (i = 0; i < SRC_COUNT; i++) {
		thread->srcs[i] = kmalloc(PAGE_SIZE, GFP_KERNEL);
		pr_debug("%s: allocated src buffer %u @0x%p\n", __func__, i, thread->srcs[i]);
		if (!thread->srcs[i])
			return -ENOMEM;
		if ((unsigned long)thread->srcs[i] & ~PAGE_MASK)
			return -EINVAL;
		memset(thread->srcs[i], i, PAGE_SIZE);
		thread->src_dmas[i] = DMA_ERROR_CODE;
	}

	for (i = 0; i < DST_COUNT; i++) {
		thread->dsts[i] = kmalloc(PAGE_SIZE, GFP_KERNEL);
		pr_debug("%s: allocated dst buffer %u @0x%p\n", __func__, i, thread->dsts[i]);
		if (!thread->dsts[i])
			return -ENOMEM;
		if ((unsigned long)thread->dsts[i] & ~PAGE_MASK)
			return -EINVAL;
		memset(thread->dsts[i], 255 - i, PAGE_SIZE);
		thread->dst_dmas[i] = DMA_ERROR_CODE;
	}

	return 0;
}

static void dmatest_free_buffers(struct dmatest_thread *thread)
{
	unsigned int i;

	for (i = 0; i < SRC_COUNT; i++) {
		kfree(thread->srcs[i]);
		dmatest_unmap_src(thread, i);
	}

	for (i = 0; i < DST_COUNT; i++) {
		kfree(thread->dsts[i]);
		dmatest_unmap_dst(thread, i);
	}
}

static int dmatest_memcpy(struct dmatest_thread	*thread, unsigned int src,
			  unsigned int dst)
{
	DECLARE_WAIT_QUEUE_HEAD_ONSTACK(done_wait);
	struct dmatest_done done = { .wait = &done_wait };
	struct dma_chan *chan = thread->chan;
	struct dma_device *dev = chan->device;
	struct dma_async_tx_descriptor *tx;
	enum dma_status status;
	dma_cookie_t cookie;

	tx = dev->device_prep_dma_memcpy(chan, thread->dst_dmas[dst],
					 thread->src_dmas[src], PAGE_SIZE,
					 DMA_CTRL_ACK | DMA_PREP_INTERRUPT);
	if (!tx) {
		result("prep error", 0);
		return -EIO;
	}

	done.done = false;
	tx->callback = dmatest_callback;
	tx->callback_param = &done;
	cookie = tx->tx_submit(tx);

	if (dma_submit_error(cookie)) {
		result("submit error", 0);
		return -EIO;
	}
	dma_async_issue_pending(chan);

	wait_event_freezable_timeout(done_wait, done.done,
				     msecs_to_jiffies(3000));

	status = dma_async_is_tx_complete(chan, cookie, NULL, NULL);

	if (!done.done) {
		/*
		 * We're leaving the timed out dma operation with
		 * dangling pointer to done_wait.  To make this
		 * correct, we'll need to allocate wait_done for
		 * each test iteration and perform "who's gonna
		 * free it this time?" dancing.  For now, just
		 * leave it dangling.
		 */
		result("test timed out", 0);
		return -ETIMEDOUT;
	}

	if (status != DMA_COMPLETE) {
		result(status == DMA_ERROR ?
		       "completion error status" :
		       "completion busy status", 0);
		return -EIO;
	}

	return 0;
}

static int dmatest_func(void *data)
{
	enum dmatest_buf_type trash_type = SRC_COUNT > DST_COUNT ? BUF_SRC : BUF_DST;
	enum dmatest_buf_type test_type = trash_type;

	unsigned int trash_count = max(SRC_COUNT, DST_COUNT);
	struct dmatest_thread *thread = data;
	struct dma_device *dev = thread->chan->device;
	unsigned int i;
	int ret;

	set_freezable();
	set_user_nice(current, 10);

	smp_rmb();

	/* Honor alignment restrictions */
	if (1 << dev->copy_align > PAGE_SIZE) {
		pr_err("%lu-byte buffer too small for %d-byte alignment\n",
		       PAGE_SIZE, 1 << dev->copy_align);
		ret = -EINVAL;
		goto error;
	}

	msleep(100);

	/* Allocate the buffers. */
	ret = dmatest_alloc_buffers(thread);
	if (ret < 0)
		goto error;

	pr_info("%s: testing %s side\n", __func__,
		test_type == BUF_SRC ? "src" : "dst");

	/* map 0 and 1 on the test side and 0-3 on the other side */
	for (i = 0; i < 2; ++i) {
		ret = dmatest_map(thread, test_type, i);
		if (ret < 0)
			goto error;
	}

	for (i = 0; i < 4; ++i) {
		ret = dmatest_map(thread, !test_type, i);
		if (ret < 0)
			goto error;
	}

	/* map all trash src and dst */
	for (i = 4; i < SRC_COUNT; ++i) {
		ret = dmatest_map(thread, BUF_SRC, i);
		if (ret < 0)
			goto error;
	}

	for (i = 4; i < DST_COUNT; ++i) {
		ret = dmatest_map(thread, BUF_DST, i);
		if (ret < 0)
			goto error;
	}

	/* memcpy 1 -> 1 and verify */
	pr_info("%s: memcpy 1 -> 1\n", __func__);
	ret = dmatest_memcpy(thread, 1, 1);
	if (ret < 0)
		goto error;

	dmatest_verify(thread, 1, 1, true);

	/* unmap test 1 and map test 2 instead */
	dmatest_unmap(thread, test_type, 1);
	ret = dmatest_map(thread, test_type, 2);
	if (ret < 0)
		goto error;

	/* memcpy 2 -> 2, expect 1 -> 2 */
	pr_info("%s: memcpy 2 -> 2, expect 1 -> 2\n", __func__);
	ret = dmatest_memcpy(thread, 2, 2);
	if (ret < 0)
		goto error;

	if (test_type == BUF_SRC) {
		dmatest_verify(thread, 2, 1, true);
	} else {
		dmatest_verify(thread, 1, 2, true);
		dmatest_verify(thread, 2, 255-2, true);
	}

	/* trash the tlb by memcpy all trash buffers */
	pr_info("%s: trash tlb by memcpy %u %s (4-%u)\n", __func__,
		trash_count - 4, trash_type == BUF_SRC ? "src" : "dst",
		trash_count - 1);
	for (i = 4; i < trash_count; ++i) {
		unsigned int src = trash_type == BUF_SRC ? i : 3;
		unsigned int dst = trash_type == BUF_SRC ? 3 : i;

		ret = dmatest_memcpy(thread, src, dst);
		if (ret < 0)
			goto error;

		dmatest_verify(thread, dst, src, false);
	}

	/* memcpy 2 -> 2, expect 2 -> 2 */
	pr_info("%s: memcpy 2 -> 2, expect 2 -> 2\n", __func__);
	ret = dmatest_memcpy(thread, 2, 2);
	if (ret < 0)
		goto error;

	dmatest_verify(thread, 2, 2, true);

	ret = 0;

error:
	dmatest_free_buffers(thread);

	pr_info("%s: return %d\n", current->comm, ret);

	/* terminate all transfers on specified channels */
	if (ret)
		dmaengine_terminate_all(thread->chan);

	thread->done = true;
	wake_up(&thread_wait);

	return ret;
}

static void dmatest_cleanup_channel(struct dmatest_chan *dtc)
{
	struct dmatest_thread	*thread;
	struct dmatest_thread	*_thread;
	int			ret;

	list_for_each_entry_safe(thread, _thread, &dtc->threads, node) {
		ret = kthread_stop(thread->task);
		pr_debug("thread %s exited with status %d\n",
			 thread->task->comm, ret);
		list_del(&thread->node);
		put_task_struct(thread->task);
		kfree(thread);
	}

	/* terminate all transfers on specified channels */
	dmaengine_terminate_all(dtc->chan);

	kfree(dtc);
}

static int dmatest_add_threads(struct dmatest_chan *dtc)
{
	struct dmatest_thread *thread;
	struct dma_chan *chan = dtc->chan;

	thread = kzalloc(sizeof(struct dmatest_thread), GFP_KERNEL);
	if (!thread) {
		pr_warn("No memory for %s-copy\n",
			dma_chan_name(chan));
		return -ENOMEM;
	}

	thread->chan = dtc->chan;
	smp_wmb();

	thread->task = kthread_create(dmatest_func, thread, "%s-copy",
			dma_chan_name(chan));
	if (IS_ERR(thread->task)) {
		pr_warn("Failed to create thread %s-copy\n",
			dma_chan_name(chan));
		kfree(thread);
		return PTR_ERR(thread->task);
	}

	/* srcbuf and dstbuf are allocated by the thread itself */
	get_task_struct(thread->task);
	list_add_tail(&thread->node, &dtc->threads);
	wake_up_process(thread->task);

	return 1;
}

static int dmatest_add_channel(struct dmatest_info *info,
		struct dma_chan *chan)
{
	struct dmatest_chan	*dtc;
	unsigned int		thread_count = 0;
	int cnt;

	dtc = kmalloc(sizeof(struct dmatest_chan), GFP_KERNEL);
	if (!dtc) {
		pr_warn("No memory for %s\n", dma_chan_name(chan));
		return -ENOMEM;
	}

	dtc->chan = chan;
	INIT_LIST_HEAD(&dtc->threads);

	cnt = dmatest_add_threads(dtc);
	thread_count += cnt > 0 ? cnt : 0;

	pr_info("Started %u threads using %s\n",
		thread_count, dma_chan_name(chan));

	list_add_tail(&dtc->node, &info->channels);
	info->nr_channels++;

	return 0;
}

static void run_threaded_test(struct dmatest_info *info)
{
	struct dma_chan *chan;
	dma_cap_mask_t mask;

	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY, mask);

	chan = dma_request_channel(mask, NULL, NULL);
	if (!chan) {
		pr_err("Unable to find DMA channel\n");
		return;
	}

	if (dmatest_add_channel(info, chan))
		dma_release_channel(chan);
}

static void stop_threaded_test(struct dmatest_info *info)
{
	struct dmatest_chan *dtc, *_dtc;
	struct dma_chan *chan;

	list_for_each_entry_safe(dtc, _dtc, &info->channels, node) {
		list_del(&dtc->node);
		chan = dtc->chan;
		dmatest_cleanup_channel(dtc);
		pr_debug("dropped channel %s\n", dma_chan_name(chan));
		dma_release_channel(chan);
	}

	info->nr_channels = 0;
}

static int __init dmatest_init(void)
{
	struct dmatest_info *info = &test_info;

	mutex_lock(&info->lock);
	run_threaded_test(info);
	mutex_unlock(&info->lock);

	return 0;
}
/* when compiled-in wait for drivers to load first */
late_initcall(dmatest_init);

static void __exit dmatest_exit(void)
{
	struct dmatest_info *info = &test_info;

	mutex_lock(&info->lock);
	stop_threaded_test(info);
	mutex_unlock(&info->lock);
}
module_exit(dmatest_exit);

MODULE_AUTHOR("Haavard Skinnemoen (Atmel)");
MODULE_LICENSE("GPL v2");
