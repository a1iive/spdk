#include "core/env.h" // for YCSB-C
// #include "mongo/db/storage/wiredtiger/wiredtiger_env.h"  // for mongodb

extern "C" {
    #include "spdk/env.h"
    #include "spdk/event.h"
    #include "spdk/blob.h"
    #include "spdk/blobfs.h"
    #include "spdk/blob_bdev.h"
    #include "spdk/log.h"
    #include "spdk/thread.h"
    #include "spdk/bdev.h"

    #include "spdk_internal/thread.h"
}

namespace ycsbc // for YCSB-C
// namespace mongo // for mongodb
{

struct spdk_filesystem *g_wt_fs = NULL;
struct spdk_bs_dev *g_wt_bs_dev;
uint32_t g_wt_lcore = 0;
const char* g_wt_bdev_name;
const char* g_wt_dir;
pthread_t g_wt_spdkTid;
volatile bool g_wt_spdk_ready = false;
volatile bool g_wt_spdk_start_failure = false;

void SpdkInitializeThread(void);

class SpdkThreadCtx
{
public:
	struct spdk_fs_thread_ctx *channel;

	SpdkThreadCtx(void) : channel(NULL)
	{
		SpdkInitializeThread();
	}

	~SpdkThreadCtx(void)
	{
		if (channel) {
			spdk_fs_free_thread_ctx(channel);
			channel = NULL;
		}
	}

private:
	SpdkThreadCtx(const SpdkThreadCtx &);
	SpdkThreadCtx &operator=(const SpdkThreadCtx &);
};

thread_local SpdkThreadCtx g_wt_sync_args;

static void
set_channel()
{
	struct spdk_thread *thread;

	if (g_wt_fs != NULL && g_wt_sync_args.channel == NULL) {
		thread = spdk_thread_create("spdk_wiredtiger", NULL);
		spdk_set_thread(thread);
		g_wt_sync_args.channel = spdk_fs_alloc_thread_ctx(g_wt_fs);
	}
}

static void
__call_fn(void *arg1, void *arg2)
{
	fs_request_fn fn;  

	fn = (fs_request_fn)arg1;
	fn(arg2);
}

static void
__send_request(fs_request_fn fn, void *arg)
{
	struct spdk_event *event;

	event = spdk_event_allocate(g_wt_lcore, __call_fn, (void *)fn, arg);
	spdk_event_call(event);
}

void SpdkInitializeThread(void)
{
	struct spdk_thread *thread;

	if (g_wt_fs != NULL) {
		if (g_wt_sync_args.channel) {
			spdk_fs_free_thread_ctx(g_wt_sync_args.channel);
		}
		thread = spdk_thread_create("spdk_wiredtiger", NULL);
		spdk_set_thread(thread);
		g_wt_sync_args.channel = spdk_fs_alloc_thread_ctx(g_wt_fs);
	}
}

static void
fs_load_cb(__attribute__((unused)) void *ctx,
	   struct spdk_filesystem *fs, int fserrno)
{
	if (fserrno == 0) {
		g_wt_fs = fs;
	}
	g_wt_spdk_ready = true;
}

static void
base_bdev_event_cb(enum spdk_bdev_event_type type, __attribute__((unused)) struct spdk_bdev *bdev,
		   __attribute__((unused)) void *event_ctx)
{
	printf("Unsupported bdev event: type %d\n", type);
}

static void
wiredtiger_run(__attribute__((unused)) void *arg1)
{
	int rc;

    rc = spdk_bdev_create_bs_dev_ext(g_wt_bdev_name, base_bdev_event_cb, NULL,
					 &g_wt_bs_dev);

	if (rc != 0) {
		printf("Could not create blob bdev\n");
        spdk_app_stop(0);
		exit(1);
	}

	g_wt_lcore = spdk_env_get_first_core();

	printf("using bdev %s\n", g_wt_bdev_name);
	spdk_fs_load(g_wt_bs_dev, __send_request, fs_load_cb, NULL);
}

static void
fs_unload_cb(__attribute__((unused)) void *ctx,
	     __attribute__((unused)) int fserrno)
{
	assert(fserrno == 0);

	spdk_app_stop(0);
}

static void 
wiredtiger_shutdown()
{
    if (g_wt_fs != NULL) {
		spdk_fs_unload(g_wt_fs, fs_unload_cb, NULL);
	} else {
		fs_unload_cb(NULL, 0);
	}
}

static void *
initialize_spdk(void *arg)
{
	struct spdk_app_opts *opts = (struct spdk_app_opts *)arg;
	int rc;

	rc = spdk_app_start(opts, wiredtiger_run, NULL);
	/*
	 * TODO:  Revisit for case of internal failure of
	 * spdk_app_start(), itself.  At this time, it's known
	 * the only application's use of spdk_app_stop() passes
	 * a zero; i.e. no fail (non-zero) cases so here we
	 * assume there was an internal failure and flag it
	 * so we can throw an exception.
	 */
	if (rc) {
		g_wt_spdk_start_failure = true;
	} else {
		spdk_app_fini();
		free(opts);
	}
	pthread_exit(NULL);

}

void 
spdk_init_env(/* WT_SESSION_IMPL *session, */ const char *conf, 
		 const char *bdev, uint64_t cache_size_in_mb) 
{
    struct spdk_app_opts *opts = new struct spdk_app_opts;

	spdk_app_opts_init(opts, sizeof(*opts));
	opts->name = "wiredtiger";
	opts->json_config_file = conf;
	opts->shutdown_cb = wiredtiger_shutdown;
    opts->tpoint_group_mask = "0x80";

	spdk_fs_set_cache_size(cache_size_in_mb);
	g_wt_bdev_name = bdev;
    // initialize_spdk(opts);
	pthread_create(&g_wt_spdkTid, NULL, &initialize_spdk, opts);
	while (!g_wt_spdk_ready && !g_wt_spdk_start_failure)
		;
	if (g_wt_spdk_start_failure) {
		free(opts);
        SPDK_ERRLOG("spdk_app_start() unable to start wiredtiger_run()");
        // __wt_err(session, WT_ERROR,
        //   "spdk_app_start() unable to start wiredtiger_run()");
	}

	SpdkInitializeThread();
}

void
spdk_close_env()
{
    if (g_wt_fs != NULL) { 
		spdk_fs_iter iter;
		struct spdk_file *file;

		if (!g_wt_sync_args.channel) {
			SpdkInitializeThread();
		}

		iter = spdk_fs_iter_first(g_wt_fs);
		while (iter != NULL) {
			file = spdk_fs_iter_get_file(iter);
			spdk_file_close(file, g_wt_sync_args.channel);
			iter = spdk_fs_iter_next(iter);
		}
	}

	spdk_app_start_shutdown();
	pthread_join(g_wt_spdkTid, NULL);
}

// fs_directory_list
int spdk_fs_directory_list(const char *directory,
  const char *prefix, char ***dirlistp, uint32_t *countp, bool single) 
{
    struct spdk_file *file;
    spdk_fs_iter iter;
	size_t len, prefix_len;
    uint32_t allocated, count;
    int ret = 0;
    const char *name;
    char **entries;
    void *p;

    *dirlistp = NULL;
    *countp = 0;

    entries = NULL;
    allocated = count = 0;
    len = strlen(directory);
    prefix_len = prefix == NULL ? 0 : strlen(prefix);
    
    iter = spdk_fs_iter_first(g_wt_fs);
	while(iter != NULL) {
        file = spdk_fs_iter_get_file(iter);
        name = spdk_file_get_name(file);
        if (strncmp(name, directory, len) != 0 ||
          (prefix != NULL && strncmp(name, prefix, prefix_len) != 0)){
              iter = spdk_fs_iter_next(iter);
              continue;
          }

        // if (strncmp(name, directory, len) != 0) {
        //     spdk_fs_iter_next(iter);
        //     continue;
        // }
            

        /*
         * Increase the list size in groups of 10, it doesn't matter if the list is a bit longer
         * than necessary.
         */
        if (count >= allocated) {
            p = realloc(entries, (allocated + 10) * sizeof(*entries));
            if (p == NULL) {
                ret = ENOMEM;
                goto err;
            }

            entries = (char**)p;
            memset(entries + allocated * sizeof(*entries), 0, 10 * sizeof(*entries));
            allocated += 10;
        }
        entries[count++] = strdup(name);
        if(single) break;
        iter = spdk_fs_iter_next(iter);
    }
	
    *dirlistp = entries;
    *countp = count;
err:
	if (ret == 0)
        return (0);

    if (entries != NULL) {
        while (count > 0)
            free(entries[--count]);
        free(entries);
    }

    return (ret);
}

int spdk_fs_directory_list_free(char **dirlist, uint32_t count)
{
    if (dirlist != NULL) {
        while (count > 0)
            free(dirlist[--count]);
        free(dirlist);
    }
    return (0);
}

int spdk_open_file(struct spdk_file_fd **fd, const char *name/*, int file_type*/)
{
    // char *path;
    struct spdk_file *file;
    int rc;
    uint8_t file_type;

    // path = NULL;
    *fd = (struct spdk_file_fd *)calloc(1, sizeof(**fd));
    // TODO : 是否所有name传参都可能是文件名，还是都是绝对路径
    // WT_RET(__wt_filename(session, name, &path));
    const char *fname = basename(name);

    if(strncmp(fname, "index", 5) == 0) {
        // index file
        file_type = 3;
    } else if(strncmp(fname, "collection", 10) == 0 || strcmp(fname, "ycsb_wiredtiger.wt") == 0) { 
        // ycsb_wiredtiger.wt is wiredtiger data file in YCSB-C 
        // data file
        file_type = 2;
    } else if(strncmp(fname, "WiredTigerLog", 13) == 0 || strncmp(fname, "WiredTigerPreplog", 17) == 0 || 
                strncmp(fname, "WiredTigerTmplog", 16) == 0) {
        // log file
        file_type = 1;
    } else {
        // metadata file
        file_type = 0;
    }

    set_channel();
    /*
    if (file_type == 0){
        rc = spdk_fs_open_file_ms(g_wt_fs, g_wt_sync_args.channel,
                        name, 0, &file, file_type);
    }
    else {
        rc = spdk_fs_open_file_ms(g_wt_fs, g_wt_sync_args.channel,
                        name, SPDK_BLOBFS_OPEN_CREATE, &file, file_type);
    }
    */
    rc = spdk_fs_open_file_ms(g_wt_fs, g_wt_sync_args.channel,
                        name, SPDK_BLOBFS_OPEN_CREATE, &file, file_type);

    if(rc == 0) {
        (*fd)->mFile = file;
        return 0;
    } else {
        return -1;
    }

}

int spdk_fs_exist(const char *name)
{
    struct spdk_file_stat stat;
	int rc;

    set_channel();
    rc = spdk_fs_file_stat(g_wt_fs, g_wt_sync_args.channel, name, &stat);
    if (rc == 0) {
        return 0;
    }
    // return WT_ERROR;
    return ENOENT;
}

int spdk_fs_remove(const char *name)
{
    int rc;

    set_channel();
    rc = spdk_fs_delete_file(g_wt_fs, g_wt_sync_args.channel, name);
    if (rc == -ENOENT) {
        return ENOENT;
    }
    return 0;
}

int spdk_fs_rename(const char *from, const char *to)
{
    int rc;
    set_channel();
    rc = spdk_fs_rename_file(g_wt_fs, g_wt_sync_args.channel,
                    from, to);
    if (rc == -ENOENT) {
        return ENOENT;
    }
    return 0;
}

int spdk_fs_size(const char *name, off_t *sizep)
{
    struct spdk_file_stat stat;
    int rc;

    set_channel();
    rc = spdk_fs_file_stat(g_wt_fs, g_wt_sync_args.channel, name, &stat);
    if (rc == -ENOENT) {
        return ENOENT;
    }
    *sizep = stat.size;
    return 0;
}

int spdk_close_file(struct spdk_file_fd **fd)
{
    set_channel();
    spdk_file_close((struct spdk_file*)(*fd)->mFile, g_wt_sync_args.channel);
    (*fd)->mFile = NULL;
    free(*fd);
    return 0;
}

int spdk_size_file(struct spdk_file_fd *fd, off_t *sizep)
{
    *sizep = spdk_file_get_length((struct spdk_file *)fd->mFile);
    return 0;
}

int spdk_sync_file(struct spdk_file_fd *fd)
{
    int rc;

    set_channel();
    rc = spdk_file_sync((struct spdk_file *)fd->mFile, g_wt_sync_args.channel);
    if (!rc) {
        return 0;
    } else {
        return -rc;
    }
}

int64_t spdk_read_file(struct spdk_file_fd *fd, off_t offset, size_t len, void *buf)
{
    int64_t rc;

	set_channel();

	rc = spdk_file_read_ms((struct spdk_file *)fd->mFile, g_wt_sync_args.channel, buf, offset, len);

	
    return rc;
}

int spdk_write_file(struct spdk_file_fd *fd, off_t offset, size_t len, void *buf)
{
    int64_t rc;

	set_channel();
	rc = spdk_file_write_ms((struct spdk_file *)fd->mFile, g_wt_sync_args.channel, buf, offset, len);
    
	return rc;
}

int spdk_truncate_file(struct spdk_file_fd *fd, off_t len)
{
    int rc;

    set_channel();
    rc = spdk_file_truncate((struct spdk_file *)fd->mFile, g_wt_sync_args.channel, len);
    if (!rc) {
        return 0;
    } else {
        return -rc;
    }
}

} // namespace ycsbc