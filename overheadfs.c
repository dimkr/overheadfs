/*
 * this file is part of overheadfs.
 *
 * Copyright (C) 2017 Dima Krasner
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <dirent.h>

#include <fuse.h>

/* libc redefines the AT_* constants instead of including the kernel header, but
 * at least some glibc versions do not define AT_EMPTY_PATH */
#ifndef AT_EMPTY_PATH
#	define AT_EMPTY_PATH 0x1000
#endif

static int ovfs_open(const char *name, struct fuse_file_info *fi)
{
	int fd;

	fd = openat((int)(intptr_t)(fuse_get_context()->private_data),
	            &name[1],
	            fi->flags);
	if (fd < 0)
		return -errno;

	fi->fh = (uint64_t)fd;
	return 0;
}

static int ovfs_create(const char *name,
                       mode_t mode,
                       struct fuse_file_info *fi)
{
	const struct fuse_context *ctx;
	int dirfd, fd, err;

	ctx = fuse_get_context();
	dirfd = (int)(intptr_t)ctx->private_data;

	fd = openat(dirfd, &name[1], fi->flags | O_CREAT | O_EXCL, mode);
	if (fd < 0)
		return -errno;

	if (fchown(fd, ctx->uid, ctx->gid) < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	fi->fh = (uint64_t)fd;
	return 0;
}

static int ovfs_close(const char *name, struct fuse_file_info *fi)
{
	if (close((int)fi->fh))
		return -errno;

	return 0;
}

#if FUSE_USE_VERSION < 30
static int ovfs_truncate(const char *name, off_t size)
#else
static int ovfs_truncate(const char *name,
                         off_t size,
                         struct fuse_file_info *fi)
#endif
{
	int fd, err = 0;

#if FUSE_USE_VERSION >= 30
	if (fi)
		fd = (int)fi->fh;
	else {
#endif
		fd = openat((int)(intptr_t)(fuse_get_context()->private_data),
		            &name[1],
		            O_WRONLY | O_CREAT);
		if (fd < 0)
			return -errno;
#if FUSE_USE_VERSION >= 30
	}
#endif

	if (ftruncate(fd, size) < 0)
		err = -errno;

#if FUSE_USE_VERSION >= 30
	if (!fi)
		close(fd);
#endif

	return err;
}

static int ovfs_getattr(const char *name,
#if FUSE_USE_VERSION < 30
                        struct stat *stbuf)
#else
                        struct stat *stbuf,
                        struct fuse_file_info *fi)

#endif
{
	int ret;

#if FUSE_USE_VERSION >= 30
	if (fi)
		ret = fstat((int)fi->fh, stbuf);
	else
#endif
		ret = fstatat((int)(intptr_t)(fuse_get_context()->private_data),
	                  &name[1],
	                  stbuf,
	                  AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);

	if (ret < 0)
		return -errno;

	return 0;
}

static int ovfs_access(const char *name, int mask)
{
	const char *namep = name;

	if ((name[0] != '/') || (name[1] != '\0'))
		++namep;

	if (faccessat((int)(intptr_t)(fuse_get_context()->private_data),
	              namep,
	              mask,
	              AT_SYMLINK_NOFOLLOW) < 0)
		return -errno;

	return 0;
}

static int ovfs_read(const char *path,
                     char *buf,
                     size_t size,
                     off_t off,
                     struct fuse_file_info *fi)
{
	ssize_t out;

	out = pread((int)fi->fh, buf, size > INT_MAX ? INT_MAX : size, off);
	if (out < 0)
		return -errno;

	return (int)out;
}

static int ovfs_write(const char *path,
                      const char *buf,
                      size_t size,
                      off_t off,
                      struct fuse_file_info *fi)
{
	ssize_t out;

	out = pwrite((int)fi->fh, buf, size > INT_MAX ? INT_MAX : size, off);
	if (out < 0)
		return -errno;

	return (int)out;
}

static int ovfs_unlink(const char *name)
{
	if (unlinkat((int)(intptr_t)(fuse_get_context()->private_data),
	             &name[1],
	             0) < 0)
		return -errno;

	return 0;
}

static int ovfs_mkdir(const char *name, mode_t mode)
{
	const struct fuse_context *ctx;
	int dirfd, err;

	ctx = fuse_get_context();
	dirfd = (int)(intptr_t)ctx->private_data;

	if (mkdirat(dirfd, &name[1], mode) < 0)
		return -errno;

	if (fchownat(dirfd,
	             &name[1],
	             ctx->uid,
	             ctx->gid,
	             AT_SYMLINK_NOFOLLOW) < 0) {
		err = -errno;
		unlinkat(dirfd, &name[1], AT_REMOVEDIR);
		return err;
	}

	return 0;
}

static int ovfs_rmdir(const char *name)
{
	if (unlinkat((int)(intptr_t)(fuse_get_context()->private_data),
	             &name[1],
	             AT_REMOVEDIR) < 0)
		return -errno;

	return 0;
}

static int ovfs_opendir(const char *name, struct fuse_file_info *fi)
{
	DIR *dirp;
	int fd, err, dirfd = (int)(intptr_t)(fuse_get_context()->private_data);

	if ((name[0] == '/') && (name[1] == '\0'))
		fd = dup(dirfd);
	else
		fd = openat(dirfd, &name[1], O_DIRECTORY);

	if (fd < 0)
		return -errno;

	dirp = fdopendir(fd);
	if (!dirp) {
		err = -errno;
		close(fd);
		return err;
	}

	fi->fh = (uint64_t)(uintptr_t)dirp;
	return 0;
}

static int ovfs_closedir(const char *name, struct fuse_file_info *fi)
{
	if (closedir((DIR *)(uintptr_t)fi->fh) < 0)
		return -errno;

	return 0;
}

static int ovfs_readdir(const char *path,
                        void *buf,
                        fuse_fill_dir_t filler,
                        off_t offset,
#if FUSE_USE_VERSION < 30
                        struct fuse_file_info *fi)
#else
                        struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags)
#endif
{
	struct stat stbuf;
	struct dirent ent, *pent;
	DIR *dirp = (DIR *)(uintptr_t)fi->fh;
	int dirfd = (int)(intptr_t)(fuse_get_context()->private_data);

	if (offset == 0)
		rewinddir(dirp);

	do {
		if (readdir_r(dirp, &ent, &pent) != 0)
			return -errno;

		if (!pent)
			break;

		if (fstatat(dirfd,
		            pent->d_name,
		            &stbuf,
		            AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) < 0)
			return -errno;

#if FUSE_USE_VERSION < 30
		if (filler(buf, pent->d_name, &stbuf, 0) == 1)
#else
		if (filler(buf, pent->d_name, &stbuf, 0, flags) == 1)
#endif
			return -ENOMEM;
	} while (1);

	return 0;
}

static int ovfs_symlink(const char *to, const char *from)
{
	const struct fuse_context *ctx;
	int dirfd, err;

	ctx = fuse_get_context();
	dirfd = (int)(intptr_t)ctx->private_data;

	if (symlinkat(to, dirfd, &from[1]) < 0)
		return -errno;

	if (fchownat(dirfd,
	             &from[1],
	             ctx->uid,
	             ctx->gid,
	             AT_SYMLINK_NOFOLLOW) < 0) {
		err = -errno;
		unlinkat(dirfd, &from[1], AT_REMOVEDIR);
		return err;
	}

	return 0;
}

static int ovfs_readlink(const char *name, char *buf, size_t size)
{
	ssize_t len;

	len = readlinkat((int)(intptr_t)(fuse_get_context()->private_data),
	                 &name[1],
	                 buf,
	                 size - 1);
	if (len < 0)
		return -errno;

	buf[len] = '\0';
	return 0;
}

static int ovfs_mknod(const char *name, mode_t mode, dev_t dev)
{
	if (mknodat((int)(intptr_t)(fuse_get_context()->private_data),
	            &name[1],
	            mode,
	            dev) < 0)
		return -errno;

	return 0;
}

#if FUSE_USE_VERSION < 30
static int ovfs_chmod(const char *name, mode_t mode)
#else
static int ovfs_chmod(const char *name, mode_t mode, struct fuse_file_info *fi)
#endif
{
	int ret;

#if FUSE_USE_VERSION >= 30
	if (fi)
		ret = fchmod((int)fi->fh, mode);
	else
#endif
		ret = fchmodat((int)(intptr_t)(fuse_get_context()->private_data),
	                   &name[1],
	                   mode,
	                   AT_SYMLINK_NOFOLLOW);
	if (ret < 0)
		return -errno;

	return 0;
}

static int ovfs_chown(const char *name,
                      uid_t uid,
#if FUSE_USE_VERSION < 30
                      gid_t gid)
#else
                      gid_t gid,
                      struct fuse_file_info *fi)
#endif
{
	int ret;

#if FUSE_USE_VERSION >= 30
	if (fi)
		ret = fchown((int)fi->fh, uid, gid);
	else
#endif
		ret = fchownat((int)(intptr_t)(fuse_get_context()->private_data),
		             &name[1],
		             uid,
		             gid,
		             AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);

	if (ret < 0)
		return -errno;

	return 0;
}

static int ovfs_utimens(const char *name,
#if FUSE_USE_VERSION < 30
                        const struct timespec tv[2])
#else
                        const struct timespec tv[2],
                        struct fuse_file_info *fi)
#endif
{
	int ret;

#if FUSE_USE_VERSION >= 30
	if (fi)
		ret = futimens((int)fi->fh, tv);
	else
#endif
		ret = utimensat((int)(intptr_t)(fuse_get_context()->private_data),
		                &name[1],
		                tv,
		                AT_SYMLINK_NOFOLLOW);

	if (ret < 0)
		return -errno;

	return 0;
}

static int ovfs_rename(const char *oldpath,
#if FUSE_USE_VERSION < 30
                       const char *newpath)
#else
                       const char *newpath,
                       unsigned int flags) /* XXX: handle RENAME_NOREPLACE */
#endif
{
	int dirfd = (int)(intptr_t)(fuse_get_context()->private_data);

	if (renameat(dirfd, &oldpath[1], dirfd, &newpath[1]) < 0)
		return -errno;

	return 0;
}

static struct fuse_operations ovfs_oper = {
	.open		= ovfs_open,
	.create		= ovfs_create,
	.release	= ovfs_close,

	.truncate	= ovfs_truncate,

	.read		= ovfs_read,
	.write		= ovfs_write,

	.getattr	= ovfs_getattr,
	.access		= ovfs_access,

	.unlink		= ovfs_unlink,

	.mkdir		= ovfs_mkdir,
	.rmdir		= ovfs_rmdir,

	.opendir	= ovfs_opendir,
	.releasedir	= ovfs_closedir,
	.readdir	= ovfs_readdir,

	.symlink	= ovfs_symlink,
	.readlink	= ovfs_readlink,

	.mknod		= ovfs_mknod,

	.chmod		= ovfs_chmod,
	.chown		= ovfs_chown,
	.utimens	= ovfs_utimens,
	.rename		= ovfs_rename
};

int main(int argc, char *argv[])
{
	char *fuse_argv[4];
	int dirfd, ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s TARGET\n", argv[0]);
		return EXIT_FAILURE;
	}

	dirfd = open(argv[1], O_DIRECTORY);
	if (dirfd < 0)
		return EXIT_FAILURE;

	fuse_argv[0] = argv[0];
	fuse_argv[1] = argv[1];
#if FUSE_USE_VERSION < 30
	fuse_argv[2] = "-ononempty,suid,dev,allow_other,default_permissions";
#else
	fuse_argv[2] = "-osuid,dev,allow_other,default_permissions";
#endif
	fuse_argv[3] = NULL;
	ret = fuse_main(3, fuse_argv, &ovfs_oper, (void *)(intptr_t)dirfd);

	close(dirfd);
	return ret;
}
