#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
//#include <glib.h>
#ifndef _MSC_VER
#include <sys/time.h>
#endif /* _MSC_VER */
#include "config.h"
//#include "file.h"
//#include "item.h"
#include "debug.h"
#include <pthread.h>

#if defined HAVE_API_WIN32_CE || defined _MSC_VER
#include <windows.h>
#include <windowsx.h>
#endif

pthread_rwlock_t debug_memory_rwlock;

#define DEFAULT_DEBUG_LEVEL lvl_info
dbg_level max_debug_level=DEFAULT_DEBUG_LEVEL;

int timestamp_prefix=1;

static FILE *debug_fp;

#if defined(_WIN32) || defined(__CEGCC__)

static void sigsegv(int sig) {
}

#else
#include <unistd.h>
static void sigsegv(int sig) {
    log(max_debug_level, "pid=%d", getpid());
    debug_finished();
    exit(1);
}
#endif

void debug_init() {
    int ret = 0;
    signal(SIGSEGV, sigsegv);

    debug_fp = stderr;
    debug_set_logfile("algo_debug.log");
    
    ret = pthread_rwlock_init(&debug_memory_rwlock, NULL);
    if (ret != 0) {
        dbg(lvl_error, "debug_memory_rwlock init fail ec=%d", ret);
        return;
    }
}

void debug_level_set( dbg_level level) {
    max_debug_level = level;
}

static void debug_timestamp(char *buffer) {
#if defined HAVE_API_WIN32_CE || defined _MSC_VER
    LARGE_INTEGER counter, frequency;
    double val;
    QueryPerformanceCounter(&counter);
    QueryPerformanceFrequency(&frequency);
    val=counter.HighPart * 4294967296.0 + counter.LowPart;
    val/=frequency.HighPart * 4294967296.0 + frequency.LowPart;
    sprintf(buffer,"%.6f|",val);

#else
    struct timeval tv;

    if (gettimeofday(&tv, NULL) == -1)
        return;
    /* Timestamps are UTC */
    sprintf(buffer,
            "%02d:%02d:%02d.%03d|",
            (int)(tv.tv_sec/3600)%24,
            (int)(tv.tv_sec/60)%60,
            (int)tv.tv_sec % 60,
            (int)tv.tv_usec/1000);
#endif
}

static char* dbg_level_to_string(dbg_level level) {
    switch (level) {
    case lvl_unset:
        return "-unset-";
    case lvl_error:
        return "error";
    case lvl_warning:
        return "warning";
    case lvl_info:
        return "info";
    case lvl_debug:
        return "debug";
    }
    return "-invalid level-";
}

void debug_vprintf(dbg_level level, const char *module, const int mlen, const char *function, const int flen, int prefix, const char *fmt, va_list ap) {
#if defined HAVE_API_WIN32_CE || defined _MSC_VER
    char message_origin[4096];
#else
    char message_origin[mlen+flen+3];
#endif
    memset(message_origin, 0, sizeof(message_origin));
    sprintf(message_origin, "%s:%s", module, function);
    if (max_debug_level >= level) {
        char debug_message[4096];
        memset(debug_message, 0, sizeof(debug_message));
        debug_message[0] = '\0';
        if (prefix) {
            if (timestamp_prefix)
                debug_timestamp(debug_message);
            strcpy(debug_message + strlen(debug_message), dbg_level_to_string(level));
            strcpy(debug_message + strlen(debug_message), ":");
            strcpy(debug_message + strlen(debug_message), message_origin);
            strcpy(debug_message + strlen(debug_message), ":");
        }
#if defined HAVE_API_WIN32_CE
#define vsnprintf _vsnprintf
#endif
        vsnprintf(debug_message + strlen(debug_message), sizeof(debug_message) - 1 - strlen(debug_message), fmt, ap);
#ifdef HAVE_API_WIN32_BASE
        if (strlen(debug_message) < sizeof(debug_message))
            debug_message[strlen(debug_message)] = '\r';	/* For Windows platforms, add \r at the end of the buffer (if any room) */
#endif
        if (strlen(debug_message) < sizeof(debug_message))
            debug_message[strlen(debug_message)] = '\n';	/* Add \n at the end of the buffer (if any room) */
        debug_message[sizeof(debug_message) - 1] =
            '\0';	/* Force NUL-termination of the string (if buffer size contraints did not allow for full string to fit */


        FILE *fp = debug_fp;
        if (!fp)
            fp = stderr;
        fprintf(fp, "%s", debug_message);
        fflush(fp);
    }
}

void debug_printf(dbg_level level, const char *module, const int mlen,const char *function, const int flen, int prefix, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    debug_vprintf(level, module, mlen, function, flen, prefix, fmt, ap);
    va_end(ap);
}

void debug_assert_fail(const char *module, const int mlen,const char *function, const int flen, const char *file, int line, const char *expr) {
    debug_printf(lvl_error,module,mlen,function,flen,1,"%s:%d assertion failed:%s\n", file, line, expr);
    abort();
}

void debug_destroy(void) {
    if (!debug_fp)
        return;
    if (debug_fp == stderr || debug_fp == stdout)
        return;
    fclose(debug_fp);
    debug_fp = NULL;
}

void debug_set_logfile(const char *path) {
    FILE *fp;
    fp = fopen(path, "a");
    if (fp) {
        debug_destroy();
        debug_fp = fp;
        fprintf(debug_fp, "debug log started,max debug level=%s\n", dbg_level_to_string( max_debug_level));
        fflush(debug_fp);
    }
}

struct malloc_head {
    int magic;
    int size;
    char where[256];
    char timestamp[64];
    void *return_address[8];
    struct malloc_head *prev;
    struct malloc_head *next;
} *malloc_heads;

struct malloc_tail {
    int magic;
};

int mallocs = 0;
int debug_malloc_size = 0;
int debug_malloc_size_m = 0;

void debug_dump_mallocs(void) {
    if (0 == pthread_rwlock_rdlock(&debug_memory_rwlock)) {
        struct malloc_head *head = malloc_heads;
        int i;
        dbg(lvl_info, "mallocs %d, malloced %d mb and %d b", mallocs, debug_malloc_size_m, debug_malloc_size);

        while (head) {
            //fprintf(stderr,"unfreed malloc from %s of size %d at %s\n",head->where,head->size, head->timestamp);
            dbg(lvl_info, "unfreed malloc %p from %s of size %d at %s", head, head->where, head->size, head->timestamp);
#if 0
            for (i = 0; i < 8; i++) {
                //fprintf(stderr, "\tlist *%p\n", head->return_address[i]);
                dbg(lvl_info, "\tlist *%p", head->return_address[i]);
            }
#endif
            head = head->next;
        }
        pthread_rwlock_unlock(&debug_memory_rwlock);
    }
    else
    {
        dbg(lvl_error, "debug_memory_rwlock rdlock fail");
    }
}

void *debug_malloc(const char *where, int line, const char *func, int size) {
    struct malloc_head *head;
    struct malloc_tail *tail;
    if (!size)
        return NULL;
    if (size < 0)
    {
        dbg(lvl_error, "malloc size<0 is (%d)", size);
    }
    head=malloc(size+sizeof(struct malloc_head)+sizeof(struct malloc_tail));
    memset(head, 0, size + sizeof(struct malloc_head) + sizeof(struct malloc_tail));
    head->magic=0xdeadbeef;
    head->size=size;
    head->prev=NULL;

    //head->where=g_strdup_printf("%s:%d %s",where,line,func);
    sprintf(head->where, "%s:%d %s", where, line, func);
    debug_timestamp(head->timestamp);

#if !defined (__GNUC__)
#define __builtin_return_address(x) NULL
#endif
    head->return_address[0]=__builtin_return_address(0);
#if 0
    head->return_address[1]=__builtin_return_address(1);
    head->return_address[2]=__builtin_return_address(2);
    head->return_address[3]=__builtin_return_address(3);
    head->return_address[4]=__builtin_return_address(4);
    head->return_address[5]=__builtin_return_address(5);
    head->return_address[6]=__builtin_return_address(6);
    head->return_address[7]=__builtin_return_address(7);
#endif
    tail=(struct malloc_tail *)((unsigned char *)head+ sizeof(struct malloc_head)+ size);
    tail->magic=0xdeadbef0;

    if (0 == pthread_rwlock_wrlock(&debug_memory_rwlock)) {
        head->next = malloc_heads;
        malloc_heads = head;
        if (head->next)
            head->next->prev = head;
        head++;
        mallocs++;
        debug_malloc_size += size;

        debug_malloc_size_m += debug_malloc_size / (1024 * 1024);
        debug_malloc_size = debug_malloc_size % (1024 * 1024);
        dbg(lvl_debug, "malloced %d kb", size / 1024);
        
        pthread_rwlock_unlock(&debug_memory_rwlock);
        
    }
    else
    {
        dbg(lvl_error, "debug_memory_rwlock wrlock fail");
        dbg(lvl_error, "alloc fail from %s of size %d at %s", head->where, head->size, head->timestamp);
        free(head);
        head = NULL;
    }
    
    return head;
}


void *debug_malloc0(const char *where, int line, const char *func, int size) {
    void *ret=debug_malloc(where, line, func, size);
    if (ret)
        memset(ret, 0, size);
    return ret;
}

void *debug_realloc(const char *where, int line, const char *func, void *ptr, int size) {
    void *ret=debug_malloc(where, line, func, size);
    if (ret && ptr)
    {
        struct malloc_head *head;
        head = (struct malloc_head *)((unsigned char *)ptr - sizeof(struct malloc_head));
        struct malloc_head *head_new;
        head_new = (struct malloc_head *)((unsigned char *)ret - sizeof(struct malloc_head));
        memcpy(ret, ptr, head_new->size < head->size ? head_new->size : head->size);
    }
    debug_free(where, line, func, ptr);

    return ret;
}

char *debug_strdup(const char *where, int line, const char *func, const char *ptr) {
    int size;
    char *ret;

    if (!ptr)
        return NULL;
    size=strlen(ptr)+1;
    ret=debug_malloc(where, line, func, size);
    memcpy(ret, ptr, size);
    return ret;
}

char *debug_guard(const char *where, int line, const char *func, char *str) {
    char *ret=debug_strdup(where, line, func, str);
    g_free(str);
    return ret;
}

static void periodic_print_mallocs(int interval_seconds)
{
    static time_t last_print_time = 0; // seconds
    time_t cur_time;
    time(&cur_time);
    if (last_print_time + interval_seconds < cur_time)
    {
        last_print_time = cur_time;
        debug_dump_mallocs();
        
    }
}

//更换日志文件（需要在加锁的状态下调用）
static void periodic_change_logfile(int interval_seconds)
{
    static time_t last_print_time = 0; // seconds
    time_t cur_time;
    time(&cur_time);
    if (last_print_time + interval_seconds < cur_time)
    {
        char str_file[64];
        memset(str_file, 0, sizeof(str_file));
        sprintf(str_file, "algo_debug%ld.log", cur_time);
        debug_set_logfile(str_file);
        last_print_time = cur_time;
    }
}

void debug_free(const char *where, int line, const char *func, void *ptr) {
    struct malloc_head *head;
    struct malloc_tail *tail;
    if (!ptr)
        return;
    
    head=(struct malloc_head *)((unsigned char *)ptr-sizeof(struct malloc_head));
    tail=(struct malloc_tail *)((unsigned char *)ptr+head->size);

    if (0 == pthread_rwlock_wrlock(&debug_memory_rwlock)) {
        if (head->magic != 0xdeadbeef || tail->magic != 0xdeadbef0) {
            pthread_rwlock_unlock(&debug_memory_rwlock);
            //fprintf(stderr,"Invalid free from %s:%d %s\n",where,line,func);
            dbg(lvl_error, "Invalid free 2 from %s:%d %s", where, line, func);
            return;
        }
        head->magic = 0;
        tail->magic = 0;
        mallocs--;
        debug_malloc_size_m -= head->size / (1024 * 1024);
        debug_malloc_size -= head->size % (1024 * 1024);
        if (head->prev)
            head->prev->next = head->next;
        else
            malloc_heads = head->next;
        if (head->next)
            head->next->prev = head->prev;
        //TODO
        periodic_change_logfile(3600 * 8);

        pthread_rwlock_unlock(&debug_memory_rwlock);
        //free(head->where);
        free(head);
    }
    else
    {
        dbg(lvl_error, "debug_memory_rwlock wrlock fail");
        dbg(lvl_error, "memory leak! can't free from %s of size %d at %s", head->where, head->size, head->timestamp);
    }
    periodic_print_mallocs(15 * 60);
}

void debug_free_func(void *ptr) {
    debug_free("unknown",0,"unknown",ptr);
}

void debug_finished(void) {
    debug_dump_mallocs();
    debug_destroy();
}

