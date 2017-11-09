#include "plfs.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <map>
#include <string>
#include <iostream>
#include <vector>
#include <sys/time.h>

// #define DEBUG // DEBUG INFO SWITCH
#define endl std::endl
#define cout std::cout

#ifndef DEBUG
#define dstream cnull
#else
#define dstream cout
#endif

std::ostream cnull(0); // A temporary solution for /dev/null like stream

static FILE* (*real_fopen)(const char*, const char*) = NULL;
static int (*real_fclose)(FILE*) = NULL;
static size_t (*real_fread)(void*, size_t, size_t, FILE*) = NULL;
static size_t (*real_fwrite)(void*, size_t, size_t, FILE*) = NULL;
static FILE* (*real_tmpfile)() = NULL;
static char* (*real_realpath)(const char*, char*) = NULL;


struct Plfs_file {
    Plfs_fd* plfs_fd;
    int oflags;
    int ref_num;
    unsigned long hashed_real_path;
    char* real_path;
};

std::map<unsigned long, Plfs_file*> path_file_table;
std::map<int, Plfs_file*> fd_file_table;
std::map<int, FILE*> fd_cfile_table;

void print_tables() {
    dstream << endl << "!! PRINT fd_file_table !!" << endl;
    for (std::map<int, Plfs_file*>::const_iterator i=fd_file_table.begin(); i!=fd_file_table.end(); i++) {
        int key = i->first;
        Plfs_file* value = i->second;
        cout << key << " -> " << value << endl;
    }
    dstream << endl << "!! PRINT fd_cfile_table !!" << endl;
    for (std::map<int, FILE*>::const_iterator i=fd_cfile_table.begin(); i!=fd_cfile_table.end(); i++) {
        int key = i->first;
        FILE* value = i->second;
        cout << key << " -> " << value << endl;
    }
    dstream << endl << "!! PRINT path_file_table !!" << endl;
    for (std::map<unsigned long, Plfs_file*>::const_iterator i=path_file_table.begin(); i!=path_file_table.end(); i++) {
        unsigned long key = i->first;
        Plfs_file* value = i->second;
        cout << "hashed path: " << key << endl;
        cout << "    plfs_fd: " << value->plfs_fd;
        cout << "    oflags : " << value->oflags;
        cout << "    ref_num: " << value->ref_num << endl;
    }
    dstream << "END" << endl << endl;
}

/*
  VERY IMPORTANT
  TODO !!!
*/

char* normalize_path(const char* path) {
    real_realpath = (char* (*)(const char*, char*)) dlsym(RTLD_NEXT, "realpath");
    // char* tmp_path = (char*)malloc(sizeof(char)*strlen(path));
    // strncpy(tmp_path, path, strlen(path));
    // char* real_path = realpath(tmp_path, NULL);
    // char* t = tmp_path + strlen(path) - 1;
    // while (real_path == NULL && t >= tmp_path) {
    //     while (*t != '/' && t >= tmp_path) t--;
    //     *t = '\0';
    //     real_path = realpath(tmp_path, NULL);
    // }
    // return real_path;
    return real_realpath(path, NULL);
}


/*
  String HASH function
  From stackoverflow question 7666509

  Since we would like to check if a specific file's status, we need to
  store the currently opened filenames in a list. The process needs hashing.
*/

unsigned long string_hash(const char *str) {
    unsigned long hash = 5381, c;
    while (c = *str++) hash = ((hash << 5) + hash) + c;
    return hash;
}

// Supposed that the path here is :
// * absolute path
// * plfs path
FILE* normalized_plfs_open(const char* path, int oflags, mode_t mode) {
    Plfs_fd* plfs_fd = NULL;
    unsigned long hashed_real_path = string_hash(path);
    bool first_open = true;
    if (path_file_table.count(hashed_real_path) != 0) {
        plfs_fd = path_file_table[hashed_real_path]->plfs_fd; // Not the first time to open the file
        first_open = false;
    }
    plfs_error_t err = PLFS_EAGAIN;
    FILE* ret;
    while (err == PLFS_EAGAIN) {
        err = plfs_open(&plfs_fd, path, oflags, getpid(), mode, NULL);
    }
    if (err == PLFS_SUCCESS) {
        dstream << "plfs_open() succeed! plfs_fd = " << plfs_fd << endl;
        FILE* file = tmpfile();
        if (file != NULL) {
            int fake_fd = fileno(file);
            dstream << "tmpfile() succeed! fake_fd = " << fileno(file) << ", FILE " << file  << endl;
            Plfs_file* plfs_file;
            if (first_open) {
                plfs_file = (Plfs_file*)malloc(sizeof(struct Plfs_file));
                plfs_file->ref_num = 1;
                plfs_file->oflags = oflags;
                plfs_file->plfs_fd = plfs_fd;
                plfs_file->hashed_real_path = hashed_real_path;
                plfs_file->real_path = (char*)path;
                path_file_table[hashed_real_path] = plfs_file;
            }
            else {
                plfs_file = path_file_table[hashed_real_path];
                plfs_file->ref_num += 1;
            }
            fd_file_table[fake_fd] = plfs_file;
            ret = file;
        }
        else {
            int t_ref = 0;
            dstream << "Fake file open/create failed" << endl;
            plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &t_ref);
            ret = NULL;
        }
    }
    else {
        errno = plfs_error_to_errno(err);
        dstream << "plfs_open() failed" << endl;
        ret = NULL;
    }
    return ret;
}


// int normalized_plfs_close(FILE* file) {
//     int fd = fileno(file);
//     dstream << "Enter normalized_plfs_close()" << endl;
//     int ret;
//     Plfs_file* plfs_file = fd_file_table[fd];
//     Plfs_fd* plfs_fd = plfs_file->plfs_fd;
//     int oflags = plfs_file->oflags;
//     plfs_error_t err = PLFS_EAGAIN;
//     while (err == PLFS_EAGAIN) {
//         err = plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &(plfs_file->ref_num));
//     }
//     if (err != PLFS_SUCCESS) {
//         errno = plfs_error_to_errno(err);
//         dstream << "plfs_close() failed" << endl;
//         ret = -1;
//     }
//     else {
//         dstream << "plfs_close() succeed!" << endl;
//         ret = fclose(file);
//         if (ret == 0) {
//             dstream << "fclose() succeed!" << endl;
//             fd_file_table.erase(fd);
//             if (plfs_file->ref_num == 0) {
//                 dstream << "Ref = 0, delete the PLFS file" << endl;
//                 path_file_table.erase(plfs_file->hashed_real_path);
//                 free(plfs_file->real_path);
//                 free(plfs_file);
//             }
//         }
//         else {
//             dstream << "fclose() failed (FATAL ERROR)" << endl;
//             exit(-1);
//         }
//     }
//     return ret;
// }


// /*
//   A prototype of open() syscall w/ mode

//   *** EXPERIMENTAL ***
// */

// int _open(const char *path, int oflags, mode_t mode) {
//     dstream << "Call open() on path " << path << " with oflags " << oflags << " and mode " << mode << endl;
//     char* real_path = normalize_path(path);
//     if (real_path == NULL) {
//         dstream << "Invalid path, return -1" << endl;
//         return -1;
//     }
//     if (is_plfs_path(real_path) == 0) {
//         dstream << "Not PLFS path, return standard open()";
//         free(real_path);
//         return open(path, oflags, mode);
//     }
//     FILE* file = normalized_plfs_open(real_path, oflags, mode);
//     if (file == NULL) {
//         dstream << "normalized_plfs_open() failed" << endl;
//         return -1;
//     }
//     int fake_fd = fileno(file);
//     fd_cfile_table[fake_fd] = file;
//     dstream << "open() returns " << fake_fd << endl;
//     return fake_fd;
// }

// /*
//   The w/o mode version of open() sscall

//   *** EXPERIMENTAL ***
// */

// int _open(const char *path, int oflags) {
//     return _open(path, oflags, 0644);
// }

// // int open64;


// /*
//   A prototype of close() syscall

//   *** EXPERIMENTAL ***
// */

// int _close(int fd) {
//     dstream << "Trying to close file. fake_fd = " << fd << endl;
//     if (fd_cfile_table.count(fd) == 0) {
//         dstream << "File descriptor not found, return standard close()" << endl;
//         return close(fd);
//     }
//     FILE* file = fd_cfile_table[fd];
//     int ret = normalized_plfs_close(file);
//     if (ret != 0) {
//         dstream << "normalized_plfs_close() failed" << endl;
//         return -1;
//     }
//     fd_cfile_table.erase(fd);
//     dstream << "close() returns " << ret << endl;
//     return ret;
// }


// /*
//   A prototype of read() syscall

//   *** EXPERIMENTAL ***
// */

// ssize_t _read(int fd, void *buf, size_t nbytes) {
//     dstream << "Trying to read file. fake_fd = " << fd << endl;
//     ssize_t ret;
//     if (fd_cfile_table.count(fd) == 0) {
//         dstream << "- Invalid file descriptor, return" << endl;
//         ret = read(fd, buf, nbytes);
//     }
//     else {
//         dstream << "- File descriptor found in global fd table" << endl;
//         Plfs_file* plfs_file = fd_file_table[fd];
//         off_t offset = lseek(fd, 0, SEEK_CUR);
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_read(plfs_file->plfs_fd, (char*)buf, nbytes, offset, &ret);
//         }
//         if (err == PLFS_SUCCESS) {
//             dstream << "- File read succeed, read " << ret << "bytes" << endl;
//             lseek(fd, offset+ret, SEEK_SET);
//             dstream << "- New offset is " << lseek(fd, 0, SEEK_CUR) << endl;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             dstream << "- PLFS read failed, it returns " << err;
//         }
//     }
//     dstream << "read() returns " << ret << endl;
//     return ret;
// }


// /*
//   A prototype of write() syscall

//   *** EXPERIMENTAL ***
// */

// ssize_t _write(int fd, const void *buf, size_t nbytes) {
//     dstream << "Trying to write file. fake_fd = " << fd << endl;
//     ssize_t ret;
//     if (fd_cfile_table.count(fd) == 0) {
//         dstream << "- Invalid file descriptor, return" << endl;
//         ret = write(fd, buf, nbytes);
//     }
//     else {
//         dstream << "- File descriptor found in global fd table" << endl;
//         Plfs_file* plfs_file = fd_file_table[fd];
//         off_t offset = lseek(fd, 0, SEEK_CUR);
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_write(plfs_file->plfs_fd, (const char*)buf, nbytes, offset, getpid(), &ret);
//         }
//         if (err == PLFS_SUCCESS) {
//             dstream << "- File write succeed, write " << ret << " bytes" << endl;
//             lseek(fd, offset+ret, SEEK_SET);
//             dstream << "- New offset is " << lseek(fd, 0, SEEK_CUR) << endl;
//             // plfs_sync(plfs_file->plfs_fd);
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             dstream << "- PLFS write failed, it returns " << err;
//         }
//     }
//     dstream << "write() returns " << ret << endl;
//     return ret;
// }


// int _chmod(const char *path, mode_t mode) {
//     char* real_path = normalize_path(path);
//     int ret;
//     if (real_path == NULL) ret = -1;
//     else if (is_plfs_path(real_path) == 1) {
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_chmod(real_path, mode);
//         }
//         if (err == PLFS_SUCCESS) {
//             ret = 0;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             ret = 0;
//         }
//     }
//     else ret = chmod(path, mode);
//     free(real_path);
//     return ret;
// }


// int _fchmod(int fd, mode_t mode) {
//     int ret;
//     if (fd_file_table.count(fd) == 0) {
//         ret = fchmod(fd, mode);
//     }
//     else {
//         char* real_path = fd_file_table[fd]->real_path;
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_chmod(real_path, mode);
//         }
//         if (err == PLFS_SUCCESS) {
//             ret = 0;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             ret = 0;
//         }
//     }
//     return ret;
// }


// int _access(const char* path, int mask) {
//     char* real_path = normalize_path(path);
//     int ret;
//     if (real_path == NULL) ret = -1;
//     else if (is_plfs_path(real_path) == 1) {
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_access(real_path, mask);
//         }
//         if (err == PLFS_SUCCESS) {
//             ret = 0;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             ret = 0;
//         }
//     }
//     else ret = access(path, mask);
//     free(real_path);
//     return ret;
// }


// int _chown(const char *path, uid_t uid, gid_t gid) {
//     char* real_path = normalize_path(path);
//     int ret;
//     if (real_path == NULL) ret = -1;
//     else if (is_plfs_path(real_path) == 1) {
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_chown(real_path, uid, gid);
//         }
//         if (err == PLFS_SUCCESS) {
//             ret = 0;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             ret = 0;
//         }
//     }
//     else ret = chown(path, uid, gid);
//     free(real_path);
//     return ret;
// }


// int _fchown(int fd, uid_t uid, gid_t gid) {
//     int ret;
//     if (fd_file_table.count(fd) == 0) {
//         ret = fchown(fd, uid, gid);
//     }
//     else {
//         char* real_path = fd_file_table[fd]->real_path;
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_chown(real_path, uid, gid);
//         }
//         if (err == PLFS_SUCCESS) {
//             ret = 0;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             ret = 0;
//         }
//     }
//     return ret;
// }

int str_to_oflags(const char* mode) {
    int ret;
    int len = strlen(mode);
    char* tmp = (char*)malloc(len*sizeof(char)+1);
    int index = 0;
    for(int i=0; i<strlen(mode); i++) {
        if (mode[i] != 'b') tmp[index++] = mode[i];
    }
    tmp[index] = '\0';
    if (strcmp(tmp, "r") == 0) ret = O_RDONLY;
    else if (strcmp(tmp, "r+") == 0) ret = O_RDWR;
    else if (strcmp(tmp, "w") == 0) ret = O_WRONLY | O_TRUNC | O_CREAT;
    else if (strcmp(tmp, "w+") == 0) ret = O_RDWR | O_TRUNC | O_CREAT;
    else if (strcmp(tmp, "a") == 0) ret = O_WRONLY | O_CREAT | O_APPEND;
    else if (strcmp(tmp, "a+") == 0) ret = O_RDWR | O_CREAT | O_APPEND;
    else ret = 0;
    free(tmp);
    return ret;
}


// int _creat(const char* path, mode_t mode) {
//     return _open(path, O_CREAT|O_WRONLY|O_TRUNC, mode);
// }


// int _dup(int oldfd) {
//     int ret = dup(oldfd);
//     if (ret >= 0 && fd_file_table.count(oldfd) != 0) {
//         fd_file_table[ret] = fd_file_table[oldfd];
//     }
//     return ret;
// }


// int _dup2(int oldfd, int newfd) {
//     if (fd_file_table.count(newfd) != 0) {
//         _close(newfd);
//     }
//     int ret = dup2(oldfd, newfd);
//     if (ret >=0 && fd_file_table.count(oldfd) != 0) {
//         fd_file_table[newfd] = fd_file_table[oldfd];
//     }
//     return ret;
// }


// int _dup3(int oldfd, int newfd, int flags) {
//     if (fd_file_table.count(newfd) != 0) {
//         _close(newfd);
//     }
//     int ret = dup3(oldfd, newfd, flags);
//     if (ret >=0 && fd_file_table.count(oldfd) != 0) {
//         fd_file_table[newfd] = fd_file_table[oldfd];
//     }
//     return ret;
// }


// int _utime(const char *filename, const struct utimbuf *times) {
//     char* real_path = normalize_path(filename);
//     int ret;
//     if (is_plfs_path(real_path) == 0) {
//         ret = utime(filename, times);
//     }
//     else {
//         plfs_error_t err = plfs_utime(real_path, (struct utimbuf*)times);
//         if (err != PLFS_SUCCESS) {
//             errno = plfs_error_to_errno(err);
//             ret = -1;
//         }
//         else {
//             ret = 0;
//         }
//     }
//     free(real_path);
//     return ret;
// }


// int _utimes(const char *filename, const struct timeval times[2]) {
//     char* real_path = normalize_path(filename);
//     int ret;
//     if (is_plfs_path(real_path) == 0) {
//         ret = utimes(filename, times);
//     }
//     else {
//         utimbuf* _times = NULL;
//         if (times != NULL) {
//             _times = (utimbuf*)malloc(sizeof(utimbuf));
//             _times->actime = times[0].tv_sec;
//             _times->modtime = times[1].tv_sec;
//         }
//         plfs_error_t err = plfs_utime(real_path, _times);
//         if (err != PLFS_SUCCESS) {
//             errno = plfs_error_to_errno(err);
//             ret = -1;
//         }
//         else {
//             ret = 0;
//         }
//     }
//     free(real_path);
//     return ret;
// }

// // int _fcntl(int fd, int cmd, ... );

// // int _openat(int dirfd, const char *pathname, int flags);
// // int _openat(int dirfd, const char *pathname, int flags, mode_t mode);

// ssize_t _pread(int fd, void *buf, size_t count, off_t offset) {
//     ssize_t ret;
//     if (fd_file_table.count(fd) == 0) {
//         ret = pread(fd, buf, count, offset);
//     }
//     else {
//         Plfs_file* plfs_file = fd_file_table[fd];
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_read(plfs_file->plfs_fd, (char*)buf, count, offset, &ret);
//         }
//         if (err != PLFS_SUCCESS) {
//             errno = plfs_error_to_errno(err);
//         }
//     }
//     dstream << "pread() returns " << ret << endl;
//     return ret;
// }

// ssize_t _pwrite(int fd, const void *buf, size_t count, off_t offset) {
//     ssize_t ret;
//     if (fd_file_table.count(fd) == 0) {
//         ret = pwrite(fd, buf, count, offset);
//     }
//     else {
//         Plfs_file* plfs_file = fd_file_table[fd];
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_write(plfs_file->plfs_fd, (const char*)buf, count, offset, getpid(), &ret);
//         }
//         if (err != PLFS_SUCCESS) {
//             errno = plfs_error_to_errno(err);
//         }
//     }
//     dstream << "pwrite() returns " << ret << endl;
//     return ret;
// }


// int _truncate(const char *path, off_t length) {
//     char* real_path = normalize_path(path);
//     int ret;
//     if (is_plfs_path(real_path) == 0) {
//         ret = truncate(path, length);
//     }
//     else {
//         plfs_error_t err = plfs_trunc(NULL, path, length, 0);
//         if (err != PLFS_SUCCESS) {
//             errno = plfs_error_to_errno(err);
//             ret = -1;
//         }
//         else {
//             ret = 0;
//         }
//     }
//     free(real_path);
//     return ret;
// }


// // int _truncate64(const char* path, off_t length);
// // int _ftruncate(int fd, off_t length);
// // int _ftruncate64(int fd, off_t length);


// void _sync(void) {
//     for (std::map<int, Plfs_file*>::iterator i=fd_file_table.begin(); i!=fd_file_table.end(); i++) {
//         Plfs_file* f = i->second;
//         plfs_sync(f->plfs_fd);
//     }
//     sync();
// }


// int _syncfs(int fd) {
//     int ret;
//     if (fd_file_table.count(fd) == 0) {
//         ret = syncfs(fd);
//     }
//     else {
//         plfs_error_t err = plfs_sync(fd_file_table[fd]->plfs_fd);
//         if (err != PLFS_SUCCESS) {
//             ret = -1;
//             errno = plfs_error_to_errno(err);
//         }
//         else ret = 0;
//     }
//     return ret;
// }


// int _fsync(int fd) {
//     return _syncfs(fd);
// }


// int _fdatasync(int fd) {
//     return _syncfs(fd);
// }







FILE* fopen(const char *path, const char* mode) {
    real_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");

    dstream << "Call open on path " << path << " with mode " << mode << endl;
    char* real_path = normalize_path(path);
    if (real_path == NULL) {
        dstream << "Invalid path, return -1" << endl;
        return NULL;
    }
    if (is_plfs_path(real_path) == 0) {
        dstream << "Not PLFS path, return standard fopen()";
        free(real_path);
        return real_fopen(path, mode);
    }
    int oflags = str_to_oflags(mode);
    dstream << "- openflags " << oflags << endl;
    FILE* file = normalized_plfs_open(real_path, oflags, 0644);
    if (file == NULL) {
        dstream << " - Normalized open failed" << endl;
        return NULL;
    }
    return file;
}


// int fclose(FILE* file) {
//     dstream << "Call close on file" << file << endl;
//     int fd = fileno(file);
//     if (fd_file_table.count(fd) == 0) {
//         dstream << "File descriptor not found, return standard fclose()" << endl;
//         return fclose(file);
//     }
//     int ret = normalized_plfs_close(file);
//     if (ret != 0) {
//         dstream << "normalized_plfs_close() failed" << endl;
//         return -1;
//     }
//     dstream << "fclose() returns " << ret << endl;
//     return ret;
// }


// size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
//     ssize_t ret;
//     int fd = fileno(stream);
//     dstream << "Trying to read file. fake_fd = " << fd << endl;
//     if (fd_file_table.count(fd) == 0) {
//         dstream << "Not in table, return normal fread()" << endl;
//         ret = fread(ptr, size, nmemb, stream);
//     }
//     else {
//         dstream << "File descriptor found in global fd table" << endl;
//         Plfs_file* plfs_file = fd_file_table[fd];
//         long offset = ftell(stream);
//         dstream << "Current offset = " << offset << endl;
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_read(plfs_file->plfs_fd, (char*)ptr, nmemb*size, offset, &ret);
//         }
//         if (err == PLFS_SUCCESS) {
//             dstream << "File read succeed, read " << ret << " units" << endl;
//             fseek(stream, ret, SEEK_CUR);
//             dstream << "New offset is " << ftell(stream) << endl;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             dstream << "- PLFS read failed, it returns " << err;
//         }
//     }
//     dstream << "fread() returns " << ret << endl;
//     return ret;
// }


// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
//     ssize_t ret;
//     int fd = fileno(stream);
//     dstream << "Trying to write file. fake_fd = " << fd << endl;
//     if (fd_file_table.count(fd) == 0) {
//         dstream << "Not in table, return normal fwrite()" << endl;
//         ret = fwrite(ptr, size, nmemb, stream);
//     }
//     else {
//         dstream << "File descriptor found in global fd table" << endl;
//         Plfs_file* plfs_file = fd_file_table[fd];
//         long offset = ftell(stream);
//         dstream << "Current offset = " << offset << endl;
//         plfs_error_t err = PLFS_EAGAIN;
//         while (err == PLFS_EAGAIN) {
//             err = plfs_write(plfs_file->plfs_fd, (const char*)ptr, nmemb*size, offset, getpid(), &ret);
//         }
//         if (err == PLFS_SUCCESS) {
//             dstream << "File read succeed, write " << ret << " units" << endl;
//             fseek(stream, ret, SEEK_CUR);
//             dstream << "New offset is " << ftell(stream) << endl;
//         }
//         else {
//             errno = plfs_error_to_errno(err);
//             dstream << "- PLFS write failed, it returns " << err;
//         }
//     }
//     dstream << "fwrite() returns " << ret << endl;
//     return ret;
// }