#include "plfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <map>
#include <string>
#include <iostream>
#include <vector>

#define DEBUG // DEBUG INFO SWITCH
#define endl std::endl
#define cout std::cout

#ifndef DEBUG
#define dstream cnull
#else
#define dstream cout
#endif


std::ostream cnull(0); // A temporary solution for /dev/null like stream

struct Plfs_file {
    Plfs_fd* plfs_fd;
    int oflags;
    int ref_num;
    unsigned long hashed_real_path;
};

std::map<int, Plfs_file*> fd_file_table;
// std::map<FILE*, Plfs_file*> cfile_file_table;
std::map<unsigned long, Plfs_file*> path_file_table;
std::map<int, FILE*> fd_cfile_table;

void print_tables() {
    dstream << endl << "!! PRINT fd_file_table !!" << endl;
    for (std::map<int, Plfs_file*>::const_iterator i=fd_file_table.begin(); i!=fd_file_table.end(); i++) {
        int key = i->first;
        Plfs_file* value = i->second;
        dstream << "fake fd: " << key << endl;
        dstream << "    plfs_fd: " << value->plfs_fd;
        dstream << "    oflags : " << value->oflags;
        dstream << "    ref_num: " << value->ref_num << endl;
    }
    dstream << endl << "!! PRINT path_file_table !!" << endl;
    for (std::map<unsigned long, Plfs_file*>::const_iterator i=path_file_table.begin(); i!=path_file_table.end(); i++) {
        unsigned long key = i->first;
        Plfs_file* value = i->second;
        dstream << "hashed path: " << key << endl;
        dstream << "    plfs_fd: " << value->plfs_fd;
        dstream << "    oflags : " << value->oflags;
        dstream << "    ref_num: " << value->ref_num << endl;
    }
    // dstream << endl << "!! PRINT fd_cfile_table !!" << endl;
    // for (std::map<FILE*, Plfs_file*>::const_iterator i=cfile_file_table.begin(); i!=cfile_file_table.end(); i++) {
    //     FILE* key = i->first;
    //     Plfs_file* value = i->second;
    //     dstream << "C file: " << key << endl;
    //     dstream << "    plfs_file: " << value;
    // }
    dstream << endl << "!! PRINT fd_cfile_table !!" << endl;
    for (std::map<int, FILE*>::const_iterator i=fd_cfile_table.begin(); i!=fd_cfile_table.end(); i++) {
        int key = i->first;
        FILE* value = i->second;
        dstream << "fake fd: " << key << endl;
        dstream << "    plfs_file: " << value;
    }
    dstream << "END" << endl << endl;
}

/*
  Loose realpath VERY IMPORTANT
  TODO
*/

char* loose_realpath(const char* path) {
    char* tmp_path = (char*)malloc(sizeof(char)*strlen(path));
    strncpy(tmp_path, path, strlen(path));
    char* real_path = realpath(tmp_path, NULL);
    char* t = tmp_path + strlen(path) - 1;
    while (real_path == NULL && t >= tmp_path) {
        while (*t != '/' && t >= tmp_path) t--;
        *t = '\0';
        real_path = realpath(tmp_path, NULL);
    }
    return real_path;
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
    char* real_path = realpath(path, NULL);
    if (real_path == NULL) {
        dstream << "Invalid path, return -1" << endl;
        return -1;
    }
    else if (is_plfs_path(real_path) == 0) {
        dstream << "Not PLFS path, return standard open()";
        free(real_path);
        return open(path, oflags, mode);
    }
    dstream << "Trying to open file " << real_path << " ";
    Plfs_fd* plfs_fd = NULL;
    unsigned long hashed_real_path = string_hash(real_path);
    dstream << hashed_real_path << endl;
    bool first_open = true;
    if (path_file_table.count(hashed_real_path) != 0) {
        plfs_fd = path_file_table[hashed_real_path]->plfs_fd; // Not the first time to open the file
        dstream << "- Not first time opening; current ref_num " << path_file_table[hashed_real_path]->ref_num << endl;
        first_open = false;
    }

    plfs_error_t err = PLFS_EAGAIN;
    int ret;
    while (err == PLFS_EAGAIN) {
        err = plfs_open(&plfs_fd, real_path, oflags, getpid(), mode, NULL);
    }
    if (err == PLFS_SUCCESS) {
        dstream << "- Open PLFS file succeed! plfs_fd = " << plfs_fd << endl;
        FILE* file = tmpfile();
        if (file != NULL) {
            int fake_fd = fileno(file);
            dstream << "- Open Fake file succeed! fake_fd = " << fileno(file) << ", FILE " << file  << endl;
            Plfs_file* plfs_file;
            if (first_open) {
                plfs_file = (Plfs_file*)malloc(sizeof(struct Plfs_file));
                plfs_file->ref_num = 1;
                plfs_file->oflags = oflags;
                plfs_file->plfs_fd = plfs_fd;
                plfs_file->hashed_real_path = hashed_real_path;
                path_file_table[hashed_real_path] = plfs_file;
            }
            else {
                plfs_file = path_file_table[hashed_real_path];
                plfs_file->ref_num += 1;
            }
            fd_file_table[fake_fd] = plfs_file;
            fd_cfile_table[fake_fd] = file;
            ret = fake_fd;
        }
        else {
            int t_ref = 0;
            dstream << "- Fake file open/create failed" << endl;
            plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &t_ref);
            ret = -1;
        }
    }
    else {
        errno = plfs_error_to_errno(err);
        dstream << "- PLFS file open failed, err = " << err << endl;
        ret = -1;
    }
    dstream << "- open() returns " << ret << endl;
    free(real_path);
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
    if (fd_file_table.count(fd) == 0) {
        dstream << "- File descriptor not found, return standard close()" << endl;
        return close(fd);
    }
    else {
        dstream << "- File descriptor found in fd_file_table" << endl;
        Plfs_file* plfs_file = fd_file_table[fd];
        Plfs_fd* plfs_fd = plfs_file->plfs_fd;
        int oflags = plfs_file->oflags;
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
            ret = close(fd);
            if (ret == 0) {
                dstream << "- Close fake file succeed!" << endl;
                fd_file_table.erase(fd);
                fclose(fd_cfile_table[fd]);
                fd_cfile_table.erase(fd);
                if (plfs_file->ref_num == 0) {
                    dstream << "- Ref = 0, delete the PLFS file" << endl;
                    path_file_table.erase(plfs_file->hashed_real_path);
                    free(plfs_file);
                }
            }
            else {
                dstream << "- Close fake file failed, it returns " << ret << endl;
                cout << "FATAL inconsistency occurs, exit!!" << endl;
                exit(-1);
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
    if (fd_file_table.count(fd) == 0) {
        dstream << "- Invalid file descriptor, return" << endl;
        ret = read(fd, buf, nbytes);
    }
    else {
        dstream << "- File descriptor found in global fd table" << endl;
        Plfs_file* plfs_file = fd_file_table[fd];
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
    if (fd_file_table.count(fd) == 0) {
        dstream << "- Invalid file descriptor, return" << endl;
        ret = write(fd, buf, nbytes);
    }
    else {
        dstream << "- File descriptor found in global fd table" << endl;
        Plfs_file* plfs_file = fd_file_table[fd];
        off_t offset = lseek(fd, 0, SEEK_CUR);
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_write(plfs_file->plfs_fd, (const char*)buf, nbytes, offset, getpid(), &ret);
        }
        if (err == PLFS_SUCCESS) {
            dstream << "- File write succeed, write " << ret << " bytes" << endl;
            lseek(fd, offset+ret, SEEK_SET);
            dstream << "- New offset is " << lseek(fd, 0, SEEK_CUR) << endl;
            // plfs_sync(plfs_file->plfs_fd);
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
//     if (fd_file_table.count(fd) == 0) {
//         ret = fchmod(fd, mode);
//     }
//     else {
//         char* real_path = fd_file_table[fd]->plfs_file->real_path;
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
//     if (fd_file_table.count(fd) == 0) {
//         ret = fchown(fd, uid, gid);
//     }
//     else {
//         char* real_path = fd_file_table[fd]->plfs_file->real_path;
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
    // int a = _open("/mnt/PLFS/test", O_RDWR);
    // dstream << a << endl;
    // print_tables();
    // int b = _open("/mnt/PLFS/test", O_RDWR);
    // print_tables();
    // int c = _open("../../../../../mnt/PLFS/test", O_RDWR);
    // print_tables();
    // int d = _open("/mnt/PLFS/test2", O_RDONLY);
    // print_tables();

    // char buf[5] = {'a', 'b', 'c', 'd', '\n'};
    // for (int i=0; i<1; i++) {
    //     _write(a, buf, 5);
    // }
    // _close(a);

    dstream << is_plfs_path("/mnt/../mnt/PLFS/test") << endl;

    print_tables();

    return 0;
}