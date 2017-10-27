#include "plfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <map>
#include <string>
#include <iostream>
#include <unistd.h>
#include <vector>

#define DEBUG // DEBUG INFO SWITCH
#define endl std::endl
#define cout std::cout

#ifndef DEBUG
#define dstream cnull
#else
#define dstream cout
#endif



// TODO LIST:
// C++ FILE*
// What can I do with errno?

std::ostream cnull(0); // A temporary solution for /dev/null like stream

struct Plfs_file {
    unsigned long hashed_real_path;
    char* real_path;
    Plfs_fd* plfs_fd;
    int ref_num;
};

struct Fd_map {
    int fake_fd;
    char* fake_path;
    int oflags;
    Plfs_file* plfs_file;
    // Do not need maintain offset here, use lseek(fake_fd, 0, SEEK_CUR) instead
    FILE* file; // For c++ use
};

std::map<int, Fd_map*> global_fd_table;
std::map<unsigned long, Plfs_file*> hashed_plfs_files;

void print_tables() {
    dstream << endl << "!! PRINT GLOBAL FD TABLE !!" << endl;
    for (std::map<int, Fd_map*>::const_iterator i=global_fd_table.begin(); i!=global_fd_table.end(); i++) {
        int key = i->first;
        Fd_map* value = i->second;
        dstream << "fake_fd: " << key << endl;
        dstream << " -> fake_path: " << value->fake_path;
        dstream << " oflags: " << value->oflags;
        dstream << " plfs_file: " << value->plfs_file << endl;
    }
    dstream << "!! PRINT PLFS FILE LIST !!" << endl;
    for (std::map<unsigned long, Plfs_file*>::const_iterator i=hashed_plfs_files.begin(); i!=hashed_plfs_files.end(); i++) {
        int key = i->first;
        Plfs_file* value = i->second;
        dstream << "hashed plfs path: " << key << endl;
        dstream << " -> plfs_fd: " << value->plfs_fd;
        dstream << "  ref_num: " << value->ref_num << endl;
    }
    dstream << "END" << endl << endl;
}

/*
  Random fake filename generator
  From stackoverflow question 440133

  This function will return a new allocated string address which
  points to an random file on disk.
*/

bool _SEEDED = false;
char* gen_rand_path() {
    if (!_SEEDED) { srand(time(0)); _SEEDED = true; }
    char* ret = (char*)malloc(sizeof(char)*23);
    char* _ret = ret + 10;
    for (int c; c=rand()%62, *(_ret++) = (c+"07="[(c+16)/26])*(_ret-ret<23););
    ret[22] = '\0';
    strncpy(ret, "/tmp/PLFS_", 10);
    return ret;
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


/*
  A prototype of open() syscall w/ mode

  *** EXPERIMENTAL ***
*/

int _open(const char *path, int oflags, mode_t mode) {
    char* real_path = realpath(path, NULL); // It's surprising that the realpath() syscall exists!!
    if (real_path == NULL) return -1;
    else if (is_plfs_path(real_path) == 0) {
        free(real_path);
        return open(path, oflags, mode);
    }
    dstream << "Trying to open file " << real_path << " ";
    Plfs_fd* plfs_fd = NULL;
    unsigned long hashed_real_path = string_hash(real_path);
    dstream << hashed_real_path << endl;
    bool first_open = true;
    if (hashed_plfs_files.count(hashed_real_path) != 0) {
        plfs_fd = hashed_plfs_files[hashed_real_path]->plfs_fd; // Not the first time to open the file
        dstream << "- Not first time opening; current ref_num " << hashed_plfs_files[hashed_real_path]->ref_num << endl;
        first_open = false;
    }

    plfs_error_t err = PLFS_EAGAIN;
    int ret;
    while (err == PLFS_EAGAIN) {
        err = plfs_open(&plfs_fd, real_path, oflags, getpid(), mode, NULL);
    }
    if (err == PLFS_SUCCESS) {
        dstream << "- Open PLFS file succeed! plfs_fd = " << plfs_fd << endl;
        char* fake_path = gen_rand_path();
        int fake_fd = open(fake_path, O_CREAT, mode);
        if (fake_fd >= 0) {
            dstream << "- Open Fake file succeed! fake_fd = " << fake_fd << " " << fake_path << endl;
            Fd_map* fd_map = (Fd_map*)malloc(sizeof(struct Fd_map));
            memset(fd_map, 0, sizeof(struct Fd_map));
            fd_map->fake_fd = fake_fd;
            fd_map->fake_path = fake_path;
            fd_map->oflags = oflags;
            if (first_open) {
                fd_map->plfs_file = (Plfs_file*)malloc(sizeof(struct Plfs_file));
                memset(fd_map->plfs_file, 0, sizeof(struct Plfs_file));
                fd_map->plfs_file->hashed_real_path = hashed_real_path;
                fd_map->plfs_file->real_path = real_path;
                fd_map->plfs_file->plfs_fd = plfs_fd;
                fd_map->plfs_file->ref_num = 1;
                hashed_plfs_files[hashed_real_path] = fd_map->plfs_file;
            }
            else {
                fd_map->plfs_file = hashed_plfs_files[hashed_real_path];
                fd_map->plfs_file->ref_num += 1;
            }
            global_fd_table[fake_fd] = fd_map;
            ret = fake_fd;
        }
        else {
            int t_ref = 0;
            dstream << "- Fake file open/create failed, it returns" << fake_fd << endl;
            plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &t_ref);
            ret = -1;
            free(fake_path);
        }
    }
    else {
        errno = plfs_error_to_errno(err);
        dstream << "- PLFS file open failed, err = " << err << endl;
        ret = -1;
    }
    dstream << "- open() returns " << ret << endl;
    return ret;
}

/*
  The w/o mode version of open() sscall

  *** EXPERIMENTAL ***
*/

int _open(const char *path, int oflags) {
    return _open(path, oflags, 0644);
}


/*
  A prototype of close() syscall

  *** EXPERIMENTAL ***
*/

int _close(int fd) {
    dstream << "Trying to close file. fake_fd = " << fd << endl;
    int ret;
    if (global_fd_table.count(fd) == 0) {
        dstream << "- File descriptor not found, return standard close()" << endl;
        return close(fd);
    }
    else {
        dstream << "- File descriptor found in global fd table" << endl;
        Fd_map* fd_map = global_fd_table[fd];
        Plfs_fd* plfs_fd = fd_map->plfs_file->plfs_fd;
        int fake_fd = fd_map->fake_fd;
        char* fake_path = fd_map->fake_path;
        int oflags = fd_map->oflags;
        Plfs_file* plfs_file = fd_map->plfs_file;
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &(plfs_file->ref_num));
        }
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            dstream << "- Close PLFS file failed, err = " << err << endl;
            ret = -1;
        }
        else {
            dstream << "- Close PLFS file succeed!" << endl;
            ret = close(fake_fd);
            if (ret == 0) {
                dstream << "- Close fake file succeed!" << endl;
                ret = unlink(fake_path);
                if (ret == 0) {
                    dstream << "- Unlink fake file succeed!" << endl;
                    free(fake_path);
                    free(global_fd_table[fd]);
                    global_fd_table.erase(fd);
                    if (plfs_file->ref_num == 0) {
                        dstream << "- Ref = 0, delete the PLFS file" << endl;
                        hashed_plfs_files.erase(plfs_file->hashed_real_path);
                        free(plfs_file->real_path);
                        free(plfs_file);
                    }
                }
                else {
                    dstream  << "- Unlink fake file failed, it returns " << ret << endl;
                }
            }
            else {
                dstream << "- Close fake file failed, it returns " << ret << endl;
            }
        }
    }
    dstream << "close() returns " << ret << endl;
    return ret;
}


/*
  A prototype of read() syscall

  *** EXPERIMENTAL ***
*/

ssize_t _read(int fd, void *buf, size_t nbytes) {
    dstream << "Trying to read file. fake_fd = " << fd << endl;
    ssize_t ret;
    if (global_fd_table.count(fd) == 0) {
        dstream << "- Invalid file descriptor, return" << endl;
        ret = read(fd, buf, nbytes);
    }
    else {
        dstream << "- File descriptor found in global fd table" << endl;
        Fd_map* fd_map = global_fd_table[fd];
        Plfs_file* plfs_file = fd_map->plfs_file;
        off_t offset = lseek(fd, 0, SEEK_CUR);
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, (char*)buf, nbytes, offset, &ret);
        }
        if (err == PLFS_SUCCESS) {
            dstream << "- File read succeed, read " << ret << "bytes" << endl;
            lseek(fd, offset+ret, SEEK_SET);
            dstream << "- New offset is " << lseek(fd, 0, SEEK_CUR) << endl;
        }
        else {
            errno = plfs_error_to_errno(err);
            dstream << "- PLFS read failed, it returns " << err;
        }
    }
    dstream << "read() returns " << ret << endl;
    return ret;
}


/*
  A prototype of write() syscall

  *** EXPERIMENTAL ***
*/

ssize_t _write(int fd, const void *buf, size_t nbytes) {
    dstream << "Trying to write file. fake_fd = " << fd << endl;
    ssize_t ret;
    if (global_fd_table.count(fd) == 0) {
        dstream << "- Invalid file descriptor, return" << endl;
        ret = write(fd, buf, nbytes);
    }
    else {
        dstream << "- File descriptor found in global fd table" << endl;
        Fd_map* fd_map = global_fd_table[fd];
        Plfs_file* plfs_file = fd_map->plfs_file;
        off_t offset = lseek(fd, 0, SEEK_CUR);
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_write(plfs_file->plfs_fd, (const char*)buf, nbytes, offset, getpid(), &ret);
        }
        if (err == PLFS_SUCCESS) {
            dstream << "- File write succeed, write " << ret << "bytes" << endl;
            lseek(fd, offset+ret, SEEK_SET);
            dstream << "- New offset is " << lseek(fd, 0, SEEK_CUR) << endl;
            plfs_sync(plfs_file->plfs_fd);
        }
        else {
            errno = plfs_error_to_errno(err);
            dstream << "- PLFS write failed, it returns " << err;
        }
    }
    dstream << "write() returns " << ret << endl;
    return ret;
}


int _chmod(const char *path, mode_t mode) {
    char* real_path = realpath(path, NULL);
    int ret;
    if (real_path == NULL) ret = -1;
    else if (is_plfs_path(real_path) == 1) {
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_chmod(real_path, mode);
        }
        if (err == PLFS_SUCCESS) {
            ret = 0;
        }
        else {
            errno = plfs_error_to_errno(err);
            ret = 0;
        }
    }
    else ret = chmod(path, mode);
    free(real_path);
    return ret;
}


// int _fchmod(int fd, mode_t mode) {
//     int ret;
//     if (global_fd_table.count(fd) == 0) {
//         ret = fchmod(fd, mode);
//     }
//     else {
//         char* real_path = global_fd_table[fd]->plfs_file->real_path;
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


int _access(const char* path, int mask) {
    char* real_path = realpath(path, NULL);
    int ret;
    if (real_path == NULL) ret = -1;
    else if (is_plfs_path(real_path) == 1) {
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_access(real_path, mask);
        }
        if (err == PLFS_SUCCESS) {
            ret = 0;
        }
        else {
            errno = plfs_error_to_errno(err);
            ret = 0;
        }
    }
    else ret = access(path, mask);
    free(real_path);
    return ret;
}


int _chown(const char *path, uid_t uid, gid_t gid) {
    char* real_path = realpath(path, NULL);
    int ret;
    if (real_path == NULL) ret = -1;
    else if (is_plfs_path(real_path) == 1) {
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_chown(real_path, uid, gid);
        }
        if (err == PLFS_SUCCESS) {
            ret = 0;
        }
        else {
            errno = plfs_error_to_errno(err);
            ret = 0;
        }
    }
    else ret = chown(path, uid, gid);
    free(real_path);
    return ret;
}


// int _fchown(int fd, uid_t uid, gid_t gid) {
//     int ret;
//     if (global_fd_table.count(fd) == 0) {
//         ret = fchown(fd, uid, gid);
//     }
//     else {
//         char* real_path = global_fd_table[fd]->plfs_file->real_path;
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


int _creat(const char* path, mode_t mode) {
    return _open(path, O_CREAT|O_WRONLY|O_TRUNC, mode);
}


int main() {
    int a = _open("/mnt/PLFS/test", O_RDWR);
    int b = _open("/mnt/PLFS/test", O_RDWR);
    int c = _open("../../../../../mnt/PLFS/test", O_RDWR);
    int d = _open("/mnt/PLFS/test2", O_RDONLY);

    print_tables();
    

    return 0;
}