#include "plfs.h"
#include <unordered_map>

static int (*real_open)(const char*, int, ...) = NULL;
static int (*real_close)(int) = NULL;
static ssize_t (*real_read)(int, void*, size_t) = NULL;
static ssize_t (*real_write)(int, const void*, size_t) = NULL;
static int (*real_chmod)(const char*, mode_t) = NULL;
static int (*real_fchmod)(int, mode_t) = NULL;
static int (*real_access)(const char*, int) = NULL;
static int (*real_chown)(const char*, uid_t, gid_t) = NULL;
static int (*real_fchown)(int, uid_t, gid_t) = NULL;
static int (*real_creat)(const char*, mode_t) = NULL;
static int (*real_dup)(int) = NULL;
static int (*real_dup2)(int, int) = NULL;
static int (*real_dup3)(int, int, int) = NULL;
static int (*real_utime)(const char*, const struct utimbuf*) = NULL;
static int (*real_utimes)(const char*, const struct timeval[2]) = NULL;
static int (*real_futimes)(int, const struct timeval[2]) = NULL;
static int (*real_futimens)(int, const struct timespec[2]) = NULL;
static ssize_t (*real_pread)(int, void*, size_t, off_t) = NULL;
static ssize_t (*real_pwrite)(int, const void*, size_t, off_t) = NULL;
static int (*real_truncate)(const char*, off_t) = NULL;
static void (*real_sync)() = NULL;
static int (*real_syncfs)(int) = NULL;
static int (*real_fsync)(int) = NULL;
static int (*real_fdatasync)(int) = NULL;
static FILE* (*real_fopen)(const char*, const char*) = NULL;
static int (*real_fclose)(FILE*) = NULL;
static size_t (*real_fread)(void*, size_t, size_t, FILE*) = NULL;
static size_t (*real_fwrite)(const void*, size_t, size_t, FILE*) = NULL;
static int (*real_fscanf)(FILE*, const char*, ...) = NULL;
static int (*real_fgetc)(FILE*) = NULL;
static char* (*real_fgets)(char*, int, FILE*) = NULL;
static int (*real_ungetc)(int, FILE*) = NULL;
static int (*real_fputc)(int, FILE*) = NULL;
static int (*real_fputs)(const char*, FILE*) = NULL;
static int (*real_vfprintf)(FILE*, const char*, va_list) = NULL;


struct Plfs_file {
    Plfs_fd* plfs_fd;
    int oflags;
    int ref_num;
    unsigned long hashed_real_path;
    char* real_path;
};

std::unordered_map<unsigned long, Plfs_file*> path_file_table;
std::unordered_map<int, Plfs_file*> fd_file_table;
std::unordered_map<int, FILE*> fd_cfile_table;