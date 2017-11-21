#include "stdplfs.h"
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>

/*
  Path normalization
  - convert relative path string to absolute path string
    without system calls and FUSE, pure string processing
    this implementation works possibly...
    dunno if there are any bugs

  Note: the return value is malloc(ed), so the caller should
        free the returned string in case of memory leak
*/

char* normalize_path(const char* path) {
    if (path == NULL) return NULL;
    int path_len = strlen(path);
    if (path_len < 1) return NULL;

    char* str = (char*)malloc(sizeof(char)*(path_len+1));
    memcpy(str, path, sizeof(char)*(path_len+1));
    
    if (str[0] != '/') { // need cwd
        char* cwd = getcwd(NULL, 0);
        int cwd_len = strlen(cwd);
        cwd = (char*)realloc(cwd, sizeof(char)*(path_len+cwd_len+2));
        cwd[cwd_len] = '/';
        memcpy(cwd+cwd_len+1, str, sizeof(char)*(path_len+1));
        free(str);
        str = cwd;
    }

    bool is_directory = (str[strlen(str)-1] == '/');

    char* buf[255];
    memset(buf, 0, sizeof(char*)*255);
    char *token = strtok(str, "/");
    int counter = 0;
    while (token != NULL) {
        if (strcmp(token, ".") == 0) {
            token = strtok(NULL, "/");
            continue;
        }
        if (strncmp(token, "..", 2) != 0) {
            buf[counter++] = token;
        }
        else {
            counter--;
            for (int i=2; i<strlen(token); i++) {
                if (token[i] == '.') counter--;
            }
        }
        if (counter < 0) return NULL;
        token = strtok(NULL, "/");
    }
    int out_len = 0;
    for (int i=0; i<counter; i++) {
        out_len += strlen(buf[i]);
    }
    char* out_str = (char*)malloc(sizeof(char)*(out_len+counter+1));
    int t = 0;
    for (int i=0; i<counter; i++) {
        out_str[t++] = '/';
        int t_len = strlen(buf[i]);
        memcpy(out_str+t, buf[i], t_len);
        t += t_len;
    }
    if (is_directory) {
        out_str = (char*)realloc(out_str, sizeof(char)*(++out_len+counter+1));
        out_str[out_len+counter-1] = '/';
    }
    out_str[out_len+counter] = '\0';
    free(str);
    return 0;
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
        FILE* file = tmpfile();
        if (file != NULL) {
            int fake_fd = fileno(file);
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
            plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &t_ref);
            ret = NULL;
        }
    }
    else {
        errno = plfs_error_to_errno(err);
        ret = NULL;
    }
    return ret;
}


int open(const char *path, int oflags, ...) {
    // printf("open() %s\n", path);
    real_open = (int (*)(const char*, int, ...))dlsym(RTLD_NEXT, "open");

    mode_t mode = 0;
    if ((oflags & O_CREAT) == O_CREAT) {
        va_list args;
        va_start(args, oflags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }

    char* real_path = normalize_path(path);
    if (real_path == NULL) {
        return -1;
    }
    if (is_plfs_path(real_path) == 0) {
        free(real_path);
        return real_open(path, oflags, mode);
    }
    FILE* file = normalized_plfs_open(real_path, oflags, mode);
    if (file == NULL) {
        // printf("open() failed\n");
        return -1;
    }
    int fake_fd = fileno(file);
    // printf("open() succeed with fd %d\n", fake_fd);
    fd_cfile_table[fake_fd] = file;
    return fake_fd;
}


int close(int fd) {
    if (real_close == NULL) real_close = (int (*)(int))dlsym(RTLD_NEXT, "close");

    if (fd_cfile_table.count(fd) == 0) {
        return real_close(fd);
    }
    FILE* file = fd_cfile_table[fd];
    int ret;
    Plfs_file* plfs_file = fd_file_table[fd];
    Plfs_fd* plfs_fd = plfs_file->plfs_fd;
    int oflags = plfs_file->oflags;
    plfs_error_t err = PLFS_EAGAIN;
    while (err == PLFS_EAGAIN) {
        err = plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &(plfs_file->ref_num));
    }
    if (err != PLFS_SUCCESS) {
        errno = plfs_error_to_errno(err);
        ret = -1;
    }
    else {
        ret = real_close(fd);
        if (ret == 0) {
            fd_file_table.erase(fd);
            if (plfs_file->ref_num == 0) {
                path_file_table.erase(plfs_file->hashed_real_path);
                free(plfs_file->real_path);
                free(plfs_file);
            }
        }
    }
    fd_cfile_table.erase(fd);
    return ret;
}


ssize_t read(int fd, void *buf, size_t nbytes) {
    real_read = (ssize_t (*)(int, void*, size_t))dlsym(RTLD_NEXT, "read");

    ssize_t ret;
    if (fd_cfile_table.count(fd) == 0) {
        ret = real_read(fd, buf, nbytes);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        off_t offset = lseek(fd, 0, SEEK_CUR);
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, (char*)buf, nbytes, offset, &ret);
        }
        if (err == PLFS_SUCCESS) {
            lseek(fd, offset+ret, SEEK_SET);
        }
        else {
            errno = plfs_error_to_errno(err);
        }
    }
    return ret;
}


ssize_t write(int fd, const void *buf, size_t nbytes) {
    // printf("write() on %d\n", fd);
    real_write = (ssize_t (*)(int, const void*, size_t))dlsym(RTLD_NEXT, "write");

    ssize_t ret;
    if (fd_cfile_table.count(fd) == 0) {
        ret = real_write(fd, buf, nbytes);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        off_t offset = lseek(fd, 0, SEEK_CUR);
        plfs_error_t err = PLFS_EAGAIN;
        // printf("plfs_fd %p\n", plfs_file->plfs_fd);
        while (err == PLFS_EAGAIN) {
            err = plfs_write(plfs_file->plfs_fd, (const char*)buf, nbytes, offset, getpid(), &ret);
        }
        if (err == PLFS_SUCCESS) {
            // printf("SUCC \n");
            lseek(fd, offset+ret, SEEK_SET);
        }
        else {
            errno = plfs_error_to_errno(err);
        }
    }
    return ret;
}


int chmod(const char *path, mode_t mode) {
    real_chmod = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "chmod");

    char* real_path = normalize_path(path);
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
    else ret = real_chmod(path, mode);
    free(real_path);
    return ret;
}


int fchmod(int fd, mode_t mode) {
    real_fchmod = (int (*)(int, mode_t))dlsym(RTLD_NEXT, "fchmod");

    int ret;
    if (fd_file_table.count(fd) == 0) {
        ret = real_fchmod(fd, mode);
    }
    else {
        char* real_path = fd_file_table[fd]->real_path;
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
    return ret;
}


int access(const char* path, int mask) {
    real_access = (int (*)(const char*, int))dlsym(RTLD_NEXT, "access");

    char* real_path = normalize_path(path);
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
    else ret = real_access(path, mask);
    free(real_path);
    return ret;
}


int chown(const char *path, uid_t uid, gid_t gid) {
    real_chown = (int (*)(const char*, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");

    char* real_path = normalize_path(path);
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
    else ret = real_chown(path, uid, gid);
    free(real_path);
    return ret;
}


int fchown(int fd, uid_t uid, gid_t gid) {
    real_fchown = (int (*)(int, uid_t, gid_t))dlsym(RTLD_NEXT, "fchown");

    int ret;
    if (fd_file_table.count(fd) == 0) {
        ret = real_fchown(fd, uid, gid);
    }
    else {
        char* real_path = fd_file_table[fd]->real_path;
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
    return ret;
}


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


int creat(const char* path, mode_t mode) {
    // real_creat = (int (*)(const char*, mode_t))dlsym(RTLD_NEXT, "creat");
    return open(path, O_CREAT|O_WRONLY|O_TRUNC, mode);
}


int dup(int oldfd) {
    real_dup = (int (*)(int))dlsym(RTLD_NEXT, "dup");

    int ret = real_dup(oldfd);
    if (ret >= 0 && fd_file_table.count(oldfd) != 0) {
        fd_file_table[ret] = fd_file_table[oldfd];
    }
    return ret;
}


int dup2(int oldfd, int newfd) {
    real_dup2 = (int (*)(int, int))dlsym(RTLD_NEXT, "dup2");

    if (fd_file_table.count(newfd) != 0) {
        close(newfd);
    }
    int ret = real_dup2(oldfd, newfd);
    if (ret >=0 && fd_file_table.count(oldfd) != 0) {
        fd_file_table[newfd] = fd_file_table[oldfd];
    }
    return ret;
}


int dup3(int oldfd, int newfd, int flags) {
    real_dup3 = (int (*)(int, int, int))dlsym(RTLD_NEXT, "dup3");

    if (fd_file_table.count(newfd) != 0) {
        close(newfd);
    }
    int ret = real_dup3(oldfd, newfd, flags);
    if (ret >=0 && fd_file_table.count(oldfd) != 0) {
        fd_file_table[newfd] = fd_file_table[oldfd];
    }
    return ret;
}


int utime(const char *filename, const struct utimbuf *times) {
    real_utime = (int (*)(const char*, const struct utimbuf*))dlsym(RTLD_NEXT, "utime");

    char* real_path = normalize_path(filename);
    int ret;
    if (is_plfs_path(real_path) == 0) {
        ret = real_utime(filename, times);
    }
    else {
        plfs_error_t err = plfs_utime(real_path, (struct utimbuf*)times);
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    free(real_path);
    return ret;
}


int utimes(const char *filename, const struct timeval times[2]) {
    real_utimes = (int (*)(const char*, const struct timeval[2]))dlsym(RTLD_NEXT, "utimes");

    char* real_path = normalize_path(filename);
    int ret;
    if (is_plfs_path(real_path) == 0) {
        ret = real_utimes(filename, times);
    }
    else {
        utimbuf* _times = NULL;
        utimbuf __times = {0, 0};
        if (times != NULL) {
            __times.actime = times[0].tv_sec;
            __times.modtime = times[1].tv_sec;
            _times = &__times;
        }
        plfs_error_t err = plfs_utime(real_path, _times);
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    free(real_path);
    return ret;
}

int futimes(int fd, const struct timeval times[2]) {
    real_futimes = (int (*)(int, const struct timeval[2]))dlsym(RTLD_NEXT, "futimes");

    int ret;
    if (fd_file_table.count(fd) == 0) {
        ret = real_futimes(fd, times);
    }
    else {
        char* real_path = fd_file_table[fd]->real_path;
        utimbuf* _times = NULL;
        utimbuf __times = {0, 0};
        if (times != NULL) {
            __times.actime = times[0].tv_sec;
            __times.modtime = times[1].tv_sec;
            _times = &__times;
        }
        plfs_error_t err = plfs_utime(real_path, _times);
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    return ret;
} 

int futimens(int fd, const struct timespec times[2]) {
    real_futimens = (int (*)(int, const struct timespec[2]))dlsym(RTLD_NEXT, "futimes");

    int ret;
    if (fd_file_table.count(fd) == 0) {
        ret = real_futimens(fd, times);
    }
    else {
        char* real_path = fd_file_table[fd]->real_path;
        utimbuf* _times = NULL;
        utimbuf __times = {0, 0};
        if (times != NULL) {
            __times.actime = times[0].tv_sec;
            __times.modtime = times[1].tv_sec;
            _times = &__times;
        }
        plfs_error_t err = plfs_utime(real_path, _times);
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    return ret;
}

// todo: futimensat (dir*)
// todo: utimenaat (dir*)


ssize_t pread(int fd, void *buf, size_t count, off_t offset) {
    real_pread = (ssize_t (*)(int, void*, size_t, off_t))dlsym(RTLD_NEXT, "pread");

    ssize_t ret;
    if (fd_file_table.count(fd) == 0) {
        ret = real_pread(fd, buf, count, offset);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, (char*)buf, count, offset, &ret);
        }
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
        }
    }
    return ret;
}


ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) {
    real_pwrite = (ssize_t (*)(int, const void*, size_t, off_t))dlsym(RTLD_NEXT, "pwrite");

    ssize_t ret;
    if (fd_file_table.count(fd) == 0) {
        ret = real_pwrite(fd, buf, count, offset);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_write(plfs_file->plfs_fd, (const char*)buf, count, offset, getpid(), &ret);
        }
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
        }
    }
    return ret;
}


int truncate(const char *path, off_t length) {
    real_truncate = (int (*)(const char*, off_t))dlsym(RTLD_NEXT, "truncate");

    char* real_path = normalize_path(path);
    int ret;
    if (is_plfs_path(real_path) == 0) {
        ret = real_truncate(path, length);
    }
    else {
        plfs_error_t err = plfs_trunc(NULL, path, length, 0);
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    free(real_path);
    return ret;
}


void sync(void) {
    real_sync = (void (*)())dlsym(RTLD_NEXT, "sync");

    for (std::unordered_map<int, Plfs_file*>::iterator i=fd_file_table.begin(); i!=fd_file_table.end(); i++) {
        Plfs_file* f = i->second;
        plfs_sync(f->plfs_fd);
    }
    real_sync();
}


int syncfs(int fd) {
    real_syncfs = (int (*)(int))dlsym(RTLD_NEXT, "syncfs");

    int ret;
    if (fd_file_table.count(fd) == 0) {
        ret = real_syncfs(fd);
    }
    else {
        plfs_error_t err = plfs_sync(fd_file_table[fd]->plfs_fd);
        if (err != PLFS_SUCCESS) {
            ret = -1;
            errno = plfs_error_to_errno(err);
        }
        else ret = 0;
    }
    return ret;
}


int fsync(int fd) {
    // real_fsync = (int (*)(int))dlsym(RTLD_NEXT, "fsync");
    return syncfs(fd);
}


int fdatasync(int fd) {
    // real_fdatasync = (int (*)(int))dlsym(RTLD_NEXT, "fdatasync");
    return syncfs(fd);
}


FILE* fopen(const char *path, const char* mode) {
    if (real_fopen == NULL) real_fopen = (FILE* (*)(const char*, const char*))dlsym(RTLD_NEXT, "fopen");

    char* real_path = normalize_path(path);
    if (real_path == NULL) {
        return NULL;
    }
    if (is_plfs_path(real_path) == 0) {
        free(real_path);
        return real_fopen(path, mode);
    }
    int oflags = str_to_oflags(mode);
    FILE* file = normalized_plfs_open(real_path, oflags, 0644);
    if (file == NULL) {
        return NULL;
    }
    return file;
}


int fclose(FILE* file) {
    if (real_fclose == NULL) real_fclose = (int (*)(FILE*))dlsym(RTLD_NEXT, "fclose");

    int fd = fileno(file);
    if (fd_file_table.count(fd) == 0) {
        return real_fclose(file);
    }
    Plfs_file* plfs_file = fd_file_table[fd];
    Plfs_fd* plfs_fd = plfs_file->plfs_fd;
    int oflags = plfs_file->oflags;
    plfs_error_t err = PLFS_EAGAIN;
    int ret;
    while (err == PLFS_EAGAIN) {
        err = plfs_close(plfs_fd, getpid(), getuid(), oflags, NULL, &(plfs_file->ref_num));
    }
    if (err != PLFS_SUCCESS) {
        errno = plfs_error_to_errno(err);
        ret = -1;
    }
    else {
        ret = real_fclose(file);
        if (ret == 0) {
            fd_file_table.erase(fd);
            if (plfs_file->ref_num == 0) {
                path_file_table.erase(plfs_file->hashed_real_path);
                free(plfs_file->real_path);
                free(plfs_file);
            }
        }
    }
    return ret;
}


size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    if (real_fread == NULL) real_fread = (size_t (*)(void*, size_t, size_t, FILE*))dlsym(RTLD_NEXT, "fread");

    ssize_t ret;
    int fd = fileno(stream);
    if (fd_file_table.count(fd) == 0) {
        ret = real_fread(ptr, size, nmemb, stream);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        long offset = ftell(stream);
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, (char*)ptr, nmemb*size, offset, &ret);
        }
        if (err == PLFS_SUCCESS) {
            fseek(stream, ret, SEEK_CUR);
        }
        else {
            errno = plfs_error_to_errno(err);
        }
    }
    return ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (real_fwrite == NULL) real_fwrite = (size_t (*)(const void*, size_t, size_t, FILE*))dlsym(RTLD_NEXT, "fwrite");

    ssize_t ret;
    int fd = fileno(stream);
    if (fd_file_table.count(fd) == 0) {
        ret = real_fwrite(ptr, size, nmemb, stream);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        long offset = ftell(stream);
        // long offset = lseek(fd, 0, SEEK_CUR);

        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_write(plfs_file->plfs_fd, (const char*)ptr, nmemb*size, offset, getpid(), &ret);
        }
        if (err == PLFS_SUCCESS) {
            fseek(stream, ret, SEEK_CUR);
            // lseek(fd, offset+ret, SEEK_SET);
        }
        else {
            errno = plfs_error_to_errno(err);
        }
    }
    return ret;
}


int fscanf(FILE *stream, const char *format, ...) {
    if (real_fscanf == NULL) real_fscanf = (int (*)(FILE*, const char*, ...))dlsym(RTLD_NEXT, "fscanf");

    int ret;
    int fd = fileno(stream);

    va_list args;
    va_start(args, format);

    if (fd_file_table.count(fd) == 0) {
        char bufo[BUFSIZ];
        char buft[BUFSIZ];
        Plfs_file* plfs_file = fd_file_table[fd];
        long offset = ftell(stream);
        ssize_t bytes;
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, (char*)bufo, BUFSIZ, offset, &bytes);
        }
        if (err == PLFS_SUCCESS) {
            ret = vsscanf(bufo, format, args);
            int n = vsprintf(buft, format, args);
            fseek(stream, n, SEEK_CUR);
        }
        else {
            errno = plfs_error_to_errno(err);
            ret = EOF;
        }
    }
    else {
        ret = real_fscanf(stream, format, args);
    }

    va_end(args);
    return ret;
}


int fgetc(FILE* stream) {
    if (real_fgetc == NULL) real_fgetc = (int (*)(FILE*))dlsym(RTLD_NEXT, "fgetc");

    int ret;
    int fd = fileno(stream);
    if (fd_file_table.count(fd) == 0) {
        ret = real_fgetc(stream);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        long offset = ftell(stream);
        ssize_t bytes;
        char buf;
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, &buf, sizeof(char), offset, &bytes);
        }
        if (err == PLFS_SUCCESS) {
            fseek(stream, bytes, SEEK_CUR);
        }
        else {
            errno = plfs_error_to_errno(err);
            ret = EOF;
        }
    }
    return ret;
}


char* fgets(char* s, int size, FILE* stream) {
    if (real_fgets == NULL) real_fgets = (char* (*)(char*, int, FILE*))dlsym(RTLD_NEXT, "fgets");

    char* ret = NULL;
    int fd = fileno(stream);
    if (fd_file_table.count(fd) == 0) {
        ret = real_fgets(s, size, stream);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        long offset = ftell(stream);
        ssize_t bytes;
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_read(plfs_file->plfs_fd, s, size-1, offset, &bytes);
        }
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            ret = NULL;
            stream->_flags |= _IO_ERR_SEEN;
        }
        else if (bytes == 0) {
            stream->_flags |= _IO_EOF_SEEN;
            ret = NULL;
        }
        else {
            char* eol = (char*)memchr((void*)s, '\n', bytes);
            if (eol == NULL) {
                s[size-1] = '\0';
                fseek(stream, bytes, SEEK_CUR);
            }
            else {
                *(++eol) = '\0';
                fseek(stream, eol-s, SEEK_CUR);
            }
            ret = s;
        }
    }
    return ret;
}


int getc(FILE* stream) {
    return fgetc(stream);
}


// int _IO_getc(_IO_FILE *__fp) {
//     return fgetc(__fp);
// }


// getchar()
// putchar()
// THese two method should not be implemented
// but it was implemented in LDPLFS, will check later.


int ungetc(int c, FILE* stream) {
    if (real_ungetc == NULL) real_ungetc = (int (*)(int, FILE*))dlsym(RTLD_NEXT, "ungetc");

    int ret;
    int fd = fileno(stream);
    if (fd_file_table.count(fd) == 0) {
        ret = real_ungetc(c, stream);
    }
    else {
        ret = c;
        fseek(stream, -1, SEEK_CUR);
    }
    return ret;
}


int fputc(int c, FILE* stream) {
    if (real_fputc == NULL) real_fputc = (int (*)(int, FILE*))dlsym(RTLD_NEXT, "fputc");

    int ret;
    int fd = fileno(stream);
    if (fd_file_table.count(fd) == 0) {
        ret = real_fputc(c, stream);
    }
    else {
        Plfs_file* plfs_file = fd_file_table[fd];
        long offset = ftell(stream);
        ssize_t bytes;
        plfs_error_t err = PLFS_EAGAIN;
        while (err == PLFS_EAGAIN) {
            err = plfs_write(plfs_file->plfs_fd, (const char*)&c, 1, offset, getpid(), &bytes);
        }
        if (err != PLFS_SUCCESS) {
            errno = plfs_error_to_errno(err);
            ret = EOF;
        }
        else {
            fseek(stream, bytes, SEEK_CUR);
            ret = c;
        }
    }
    return ret;
}