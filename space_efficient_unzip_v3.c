#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdint.h>
#include <libgen.h>
#include <getopt.h>
#include <time.h>
#include <linux/falloc.h>
#include <sys/sendfile.h>

#define BUFFER_SIZE 262144
#define MAX_FILENAME_LEN 4096
#define TEMP_SUFFIX ".tmp_unzip"

// ZIP文件格式常量
#define LOCAL_FILE_HEADER_SIGNATURE 0x04034b50
#define CENTRAL_DIRECTORY_SIGNATURE 0x02014b50
#define END_OF_CENTRAL_DIR_SIGNATURE 0x06054b50

// ZIP文件头结构
typedef struct {
    uint32_t signature;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression_method;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_length;
    uint16_t extra_field_length;
    // ZIP64 扩展尺寸（若存在）
    uint64_t zip64_compressed_size;
    uint64_t zip64_uncompressed_size;
} local_file_header_t;

// 中央目录记录结构
typedef struct {
    uint32_t signature;
    uint16_t version_made_by;
    uint16_t version_needed;
    uint16_t flags;
    uint16_t compression_method;
    uint16_t mod_time;
    uint16_t mod_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t filename_length;
    uint16_t extra_field_length;
    uint16_t file_comment_length;
    uint16_t disk_number_start;
    uint16_t internal_attributes;
    uint32_t external_attributes;
    uint32_t relative_offset;
} central_directory_record_t;

// 中央目录结束记录结构
typedef struct {
    uint32_t signature;
    uint16_t disk_number;
    uint16_t disk_number_start;
    uint16_t num_entries_this_disk;
    uint16_t total_entries;
    uint32_t central_directory_size;
    uint32_t central_directory_offset;
    uint16_t comment_length;
} end_of_central_directory_t;

// 全局变量用于跟踪解压目录
static char output_directory[MAX_FILENAME_LEN] = ".";
static int fast_mode = 0;
static int enable_usage_log = 1;
static size_t trim_threshold_bytes = 64 * 1024 * 1024; // 默认64MB批量裁剪

// 前置声明，供日志函数使用
int file_exists(const char *path);
off_t get_file_size(const char *path);
int is_directory_path(const char *path);

// 计算路径占用大小（文件或目录，单位：字节）
off_t get_path_size_recursive(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISREG(st.st_mode)) {
        return st.st_size;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) return 0;
        off_t total = 0;
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            char subpath[MAX_FILENAME_LEN];
            snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);
            total += get_path_size_recursive(subpath);
        }
        closedir(dir);
        return total;
    }
    // 其他类型不计入
    return 0;
}

// 记录存储占用，单位MB，写入日志文件并打印
void log_storage_usage(const char *original_path, const char *temp_path, const char *new_temp_path) {
    if (!enable_usage_log) return;
    // 构建日志文件路径（输出目录下）
    char log_path[MAX_FILENAME_LEN];
    // 输出到原始ZIP同目录下，名称: <zip>.space_unzip_usage.log
    if (original_path && strlen(original_path) < MAX_FILENAME_LEN - 32) {
        snprintf(log_path, sizeof(log_path), "%s.space_unzip_usage.log", original_path);
    } else {
        snprintf(log_path, sizeof(log_path), "space_unzip_usage.log");
    }

    off_t orig_bytes = (original_path && file_exists(original_path)) ? get_file_size(original_path) : 0;
    off_t tmp_bytes = (temp_path && file_exists(temp_path)) ? get_file_size(temp_path) : 0;
    off_t new_bytes = (new_temp_path && file_exists(new_temp_path)) ? get_file_size(new_temp_path) : 0;

    // 可选的.bak
    char bak_path[MAX_FILENAME_LEN + 5];
    off_t bak_bytes = 0;
    if (original_path) {
        snprintf(bak_path, sizeof(bak_path), "%s.bak", original_path);
        if (file_exists(bak_path)) bak_bytes = get_file_size(bak_path);
    }

    // 输出目录大小
    off_t out_bytes = 0;
    if (output_directory && file_exists(output_directory) && is_directory_path(output_directory)) {
        out_bytes = get_path_size_recursive(output_directory);
    }

    double orig_mb = (double)orig_bytes / (1024.0 * 1024.0);
    double tmp_mb = (double)tmp_bytes / (1024.0 * 1024.0);
    double new_mb = (double)new_bytes / (1024.0 * 1024.0);
    double bak_mb = (double)bak_bytes / (1024.0 * 1024.0);
    double out_mb = (double)out_bytes / (1024.0 * 1024.0);
    double total_mb = orig_mb + tmp_mb + new_mb + bak_mb + out_mb;

    // 打印到控制台
    printf("存储占用(MB): 原始=%.2f, 临时=%.2f, 新临时=%.2f, 备份=%.2f, 输出=%.2f, 总计=%.2f\n",
           orig_mb, tmp_mb, new_mb, bak_mb, out_mb, total_mb);

    // 附加到日志文件
    int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        char line[512];
        time_t now = time(NULL);
        struct tm tminfo;
        localtime_r(&now, &tminfo);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tminfo);
        int n = snprintf(line, sizeof(line),
                         "%s | origMB=%.2f tmpMB=%.2f newMB=%.2f bakMB=%.2f outMB=%.2f totalMB=%.2f\n",
                         ts, orig_mb, tmp_mb, new_mb, bak_mb, out_mb, total_mb);
        if (n > 0) (void)write(fd, line, (size_t)n);
        close(fd);
    }
}

// 原地紧缩：将文件从offset处开始的数据搬移到文件头，然后截断
int in_place_compact(const char *path, off_t offset) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0 || offset <= 0 || offset > size) {
        close(fd);
        return -1;
    }
    off_t remaining = size - offset;
    if (lseek(fd, 0, SEEK_SET) < 0) {
        close(fd);
        return -1;
    }
    const size_t buf_sz = 1 << 20; // 1MB
    unsigned char *buf = malloc(buf_sz);
    if (!buf) {
        close(fd);
        return -1;
    }
    off_t read_pos = offset;
    off_t write_pos = 0;
    while (remaining > 0) {
        size_t to_read = (remaining < (off_t)buf_sz) ? (size_t)remaining : buf_sz;
        if (lseek(fd, read_pos, SEEK_SET) < 0) { free(buf); close(fd); return -1; }
        ssize_t r = read(fd, buf, to_read);
        if (r <= 0) { free(buf); close(fd); return -1; }
        if (lseek(fd, write_pos, SEEK_SET) < 0) { free(buf); close(fd); return -1; }
        ssize_t w = write(fd, buf, r);
        if (w != r) { free(buf); close(fd); return -1; }
        read_pos += r;
        write_pos += r;
        remaining -= r;
    }
    free(buf);
    int rc = ftruncate(fd, size - offset);
    close(fd);
    return rc == 0 ? 0 : -1;
}

// 检查文件是否存在
int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

// 检查路径是否为目录
int is_directory_path(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

// 获取文件大小
off_t get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return st.st_size;
}

// 创建目录（包括父目录）
int create_directory_recursive(const char *path) {
    if (path == NULL || *path == '\0') return 0;
    
    // 检查目录是否已存在
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;  // 路径存在但不是目录
    }
    
    // 创建父目录
    char *path_copy = strdup(path);
    if (!path_copy) return -1;
    
    char *parent_dir = dirname(path_copy);
    if (strcmp(parent_dir, ".") != 0 && strcmp(parent_dir, "/") != 0) {
        if (create_directory_recursive(parent_dir) != 0) {
            free(path_copy);
            return -1;
        }
    }
    
    free(path_copy);
    
    // 创建当前目录
    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        return -1;
    }
    
    return 0;
}

// 构建输出文件路径
char* build_output_path(const char *filename) {
    char *output_path = malloc(MAX_FILENAME_LEN);
    if (!output_path) return NULL;
    
    if (strcmp(output_directory, ".") == 0) {
        snprintf(output_path, MAX_FILENAME_LEN, "%s", filename);
    } else {
        snprintf(output_path, MAX_FILENAME_LEN, "%s/%s", output_directory, filename);
    }
    
    return output_path;
}

// 读取小端序的16位整数
uint16_t read_le16(const unsigned char *data) {
    return data[0] | (data[1] << 8);
}

// 读取小端序的32位整数
uint32_t read_le32(const unsigned char *data) {
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

// 写入小端序的16位整数
void write_le16(unsigned char *data, uint16_t value) {
    data[0] = value & 0xFF;
    data[1] = (value >> 8) & 0xFF;
}

// 写入小端序的32位整数
void write_le32(unsigned char *data, uint32_t value) {
    data[0] = value & 0xFF;
    data[1] = (value >> 8) & 0xFF;
    data[2] = (value >> 16) & 0xFF;
    data[3] = (value >> 24) & 0xFF;
}

// 解析本地文件头
int parse_local_file_header(int fd, local_file_header_t *header, char **filename) {
    unsigned char buffer[46];
    
    // 读取文件头
    if (read(fd, buffer, 30) != 30) {
        return -1;
    }
    
    // 检查签名
    header->signature = read_le32(buffer);
    if (header->signature != LOCAL_FILE_HEADER_SIGNATURE) {
        return -2;
    }
    
    // 解析头字段
    header->version_needed = read_le16(buffer + 4);
    header->flags = read_le16(buffer + 6);
    header->compression_method = read_le16(buffer + 8);
    header->mod_time = read_le16(buffer + 10);
    header->mod_date = read_le16(buffer + 12);
    header->crc32 = read_le32(buffer + 14);
    header->compressed_size = read_le32(buffer + 18);
    header->uncompressed_size = read_le32(buffer + 22);
    header->filename_length = read_le16(buffer + 26);
    header->extra_field_length = read_le16(buffer + 28);
    
    // 检查文件名长度是否合理
    if (header->filename_length == 0 || header->filename_length > MAX_FILENAME_LEN) {
        return -3;
    }
    
    // 读取文件名
    *filename = malloc(header->filename_length + 1);
    if (!*filename) {
        return -4;
    }
    
    if (read(fd, *filename, header->filename_length) != header->filename_length) {
        free(*filename);
        *filename = NULL;
        return -5;
    }
    (*filename)[header->filename_length] = '\0';
    
    // 解析并跳过额外字段（处理ZIP64 extra）
    header->zip64_compressed_size = 0;
    header->zip64_uncompressed_size = 0;
    if (header->extra_field_length > 0) {
        uint16_t remain = header->extra_field_length;
        unsigned char *extra = malloc(remain);
        if (!extra) { free(*filename); *filename = NULL; return -6; }
        if (read(fd, extra, remain) != remain) { free(extra); free(*filename); *filename = NULL; return -6; }
        // 遍历extra blocks: [header_id(2), data_size(2), data]
        size_t pos = 0;
        while (pos + 4 <= remain) {
            uint16_t ex_id = read_le16(extra + pos);
            uint16_t ex_len = read_le16(extra + pos + 2);
            pos += 4;
            if (pos + ex_len > remain) break;
            if (ex_id == 0x0001) { // ZIP64 extra field
                size_t zpos = 0;
                // 按顺序存在：uncompressed_size(8)? compressed_size(8)? relative_header_offset(8)? disk_start(4)?
                if (header->uncompressed_size == 0xFFFFFFFFu && zpos + 8 <= ex_len) {
                    header->zip64_uncompressed_size = *(uint64_t *)(extra + pos + zpos);
                    zpos += 8;
                }
                if (header->compressed_size == 0xFFFFFFFFu && zpos + 8 <= ex_len) {
                    header->zip64_compressed_size = *(uint64_t *)(extra + pos + zpos);
                    zpos += 8;
                }
            }
            pos += ex_len;
        }
        free(extra);
    }
    
    return 0;
}

// 检查是否为目录（基于文件名，不以文件内容判断）
int is_directory_entry(const char *filename) {
    if (!filename) return 0;
    size_t len = strlen(filename);
    return (len > 0 && filename[len - 1] == '/');
}

// 解压单个文件（基于实际压缩方法，不依赖文件名）
// bytes_consumed: 实际从zip流中消费的压缩数据字节数（不含data descriptor）
// dd_bytes: 若存在data descriptor，表示额外跟随的描述符字节数（12或16）
// 新增参数：skip_write（1表示丢弃解压数据不写磁盘）
int inflate_file(
    int zip_fd,
    const char *output_path,
    uint32_t compressed_size,
    uint32_t uncompressed_size,
    uint16_t compression_method,
    uint16_t flags,
    uint32_t *bytes_consumed,
    uint32_t *dd_bytes,
    int skip_write
) {
    int out_fd = -1;
    if (!skip_write && output_path) {
        out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) return -1;
    }

    if (flags & 0x0001) {
        if (out_fd != -1) close(out_fd);
        return -9;
    }

    if (bytes_consumed) *bytes_consumed = 0;
    if (dd_bytes) *dd_bytes = 0;

    if (compression_method == 0) {
        // stored
        uint32_t remaining = compressed_size;
        unsigned char buffer[BUFFER_SIZE];
        if ((flags & 0x0008) && remaining == 0) {
            if (out_fd != -1) close(out_fd);
            return -10;
        }
        while (remaining > 0) {
            size_t to_read = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
            ssize_t r = read(zip_fd, buffer, to_read);
            if (r <= 0) { if (out_fd != -1) close(out_fd); return -2; }
            if (!skip_write && out_fd != -1) {
                ssize_t w = write(out_fd, buffer, r);
                if (w != r) { close(out_fd); return -7; }
            }
            if (bytes_consumed) *bytes_consumed += (uint32_t)r;
            remaining -= (uint32_t)r;
        }
    }
    else if (compression_method == 8) {
        // deflate
        z_stream strm;
        memset(&strm, 0, sizeof(strm));
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;

        int ret = inflateInit2(&strm, -MAX_WBITS);
        if (ret != Z_OK) { if (out_fd != -1) close(out_fd); return -4; }

        unsigned char in_buffer[BUFFER_SIZE];
        unsigned char out_buffer[BUFFER_SIZE];
        uint64_t total_read_from_fd = 0;
        int use_stream_end = ((flags & 0x0008) != 0) || (compressed_size == 0u || compressed_size == 0xFFFFFFFFu);

        int stream_ended = 0;
        uint32_t remaining = compressed_size;
        while (!stream_ended && (use_stream_end || remaining > 0)) {
            size_t to_read = use_stream_end ? BUFFER_SIZE : (remaining < BUFFER_SIZE ? remaining : BUFFER_SIZE);
            ssize_t bytes_read = read(zip_fd, in_buffer, to_read);
            if (bytes_read <= 0) {
                inflateEnd(&strm);
                if (out_fd != -1) close(out_fd);
                return -5;
            }
            if (!use_stream_end) remaining -= (uint32_t)bytes_read;
            total_read_from_fd += (uint64_t)bytes_read;

            strm.avail_in = (unsigned int)bytes_read;
            strm.next_in = in_buffer;

            while (strm.avail_in > 0) {
                strm.avail_out = BUFFER_SIZE;
                strm.next_out = out_buffer;
                int inflate_ret = inflate(&strm, Z_NO_FLUSH);

                if (inflate_ret == Z_NEED_DICT) {
                    inflateEnd(&strm); if (out_fd != -1) close(out_fd); return -6;
                }
                if (inflate_ret == Z_DATA_ERROR || inflate_ret == Z_MEM_ERROR) {
                    inflateEnd(&strm); if (out_fd != -1) close(out_fd); return -6;
                }

                size_t have = BUFFER_SIZE - strm.avail_out;
                if (!skip_write && have > 0 && out_fd != -1) {
                    ssize_t w = write(out_fd, out_buffer, have);
                    if (w != (ssize_t)have) {
                        inflateEnd(&strm); close(out_fd); return -7;
                    }
                }
                // skip_write 情况下直接丢弃

                if (inflate_ret == Z_STREAM_END) {
                    stream_ended = 1;
                    // 退回多余字节
                    if (strm.avail_in > 0) {
                        if (lseek(zip_fd, -(off_t)strm.avail_in, SEEK_CUR) < 0) {
                            inflateEnd(&strm); if (out_fd != -1) close(out_fd); return -11;
                        }
                        total_read_from_fd -= strm.avail_in;
                        strm.avail_in = 0;
                    }
                    break;
                }
            }
        }
        inflateEnd(&strm);
        if (bytes_consumed) *bytes_consumed = (uint32_t)total_read_from_fd;

        // --- Robust ZIP64 data descriptor skip ---
        if (flags & 0x0008) {
            // Try both: with and without signature
            unsigned char dd[32] = {0};
            ssize_t n = read(zip_fd, dd, 28); // 28足够覆盖所有变体
            if (n < 12) { if (out_fd != -1) close(out_fd); return -12; }
            size_t ddlen = 0;
            size_t off = 0;
            // Check signature
            if (read_le32(dd) == 0x08074b50) {
                off = 4;
            }
            // Try ZIP64 (crc32 + u64 + u64)
            if (off + 20 <= (size_t)n) {
                ddlen = off + 20;
            } else if (off + 16 <= (size_t)n) {
                ddlen = off + 16;
            } else if (off + 12 <= (size_t)n) {
                ddlen = off + 12;
            } else {
                // fallback
                ddlen = n;
            }
            // 常见的兼容性：有些工具写了 signature+crc+u64+u64, 有些无 signature
            // 总之尽最大可能吞下所有 data descriptor 字节
            if ((size_t)n > ddlen) lseek(zip_fd, (off_t)(ddlen - n), SEEK_CUR);
            if (dd_bytes) *dd_bytes = ddlen;
        }
        // --- end robust ZIP64 dd skip ---
    }
    else {
        if (out_fd != -1) close(out_fd);
        return -8;
    }
    if (out_fd != -1) close(out_fd);
    return 0;
}


// 将文件从offset位置复制到新文件
int copy_remaining_data(const char *src_path, const char *dest_path, off_t offset) {
    int src_fd = open(src_path, O_RDONLY);
    if (src_fd < 0) {
        perror("无法打开源文件");
        return -1;
    }

    // 获取源文件大小
    off_t src_size = lseek(src_fd, 0, SEEK_END);
    if (src_size < 0) {
        perror("获取文件大小失败");
        close(src_fd);
        return -1;
    }
    
    // 检查偏移量是否有效
    if (offset >= src_size) {
        // 偏移量超出文件大小，创建空文件
        close(src_fd);
        int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dest_fd < 0) {
            perror("无法创建目标文件");
            return -1;
        }
        close(dest_fd);
        return 0;
    }
    
    // 移动到偏移位置
    if (lseek(src_fd, offset, SEEK_SET) < 0) {
        perror("lseek失败");
        close(src_fd);
        return -1;
    }

    int dest_fd = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dest_fd < 0) {
        perror("无法创建目标文件");
        close(src_fd);
        return -1;
    }

    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    off_t remaining = src_size - offset;
    
    while (remaining > 0 && (bytes_read = read(src_fd, buffer, 
                           remaining < BUFFER_SIZE ? remaining : BUFFER_SIZE)) > 0) {
        if (write(dest_fd, buffer, bytes_read) != bytes_read) {
            perror("写入失败");
            close(src_fd);
            close(dest_fd);
            return -1;
        }
        remaining -= bytes_read;
    }

    if (bytes_read < 0) {
        perror("读取失败");
        close(src_fd);
        close(dest_fd);
        return -1;
    }

    close(src_fd);
    close(dest_fd);
    return 0;
}

// 删除文件或目录
int delete_path(const char *path) {
    if (!path || !file_exists(path)) return 0;

    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }

    // 如果是目录
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) {
            return -1;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            // 跳过.和..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            // 构建子项完整路径
            char subpath[MAX_FILENAME_LEN];
            snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);
            
            // 递归删除子项
            if (delete_path(subpath) != 0) {
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);

        // 删除空目录
        if (rmdir(path) != 0) {
            return -1;
        }
    } 
    // 如果是文件
    else {
        if (unlink(path) != 0) {
            return -1;
        }
    }

    return 0;
}

// 真正的空间高效解压
int space_efficient_unzip_v3(const char *zip_filename) {
    char temp_filename[MAX_FILENAME_LEN + strlen(TEMP_SUFFIX) + 1];
    snprintf(temp_filename, sizeof(temp_filename), "%s%s", zip_filename, TEMP_SUFFIX);
    char new_temp_filename[MAX_FILENAME_LEN + strlen(TEMP_SUFFIX) + 10];
    snprintf(new_temp_filename, sizeof(new_temp_filename), "%s.new%s", zip_filename, TEMP_SUFFIX);

    // 为实现~1倍空间占用：优先使用现有临时文件（上次中断可恢复）；否则重命名原始文件为临时文件
    if (!file_exists(temp_filename)) {
        if (file_exists(zip_filename)) {
            if (rename(zip_filename, temp_filename) != 0) {
                perror("重命名为临时文件失败");
                return -1;
            }
        } else {
            fprintf(stderr, "未找到可用的输入文件: %s 或 %s\n", zip_filename, temp_filename);
            return -1;
        }
    }

    int zip_fd = open(temp_filename, O_RDONLY);
    if (zip_fd < 0) {
        perror("无法打开临时ZIP文件");
        // 尝试将文件名改回去，避免用户文件丢失
        rename(temp_filename, zip_filename);
        return -1;
    }
    
    // 获取文件大小
    off_t file_size = lseek(zip_fd, 0, SEEK_END);
    if (file_size <= 0) {
        close(zip_fd);
        fprintf(stderr, "无效的文件大小\n");
        return -1;
    }
    
    // 回到文件开头
    if (lseek(zip_fd, 0, SEEK_SET) < 0) {
        close(zip_fd);
        perror("无法定位到文件开头");
        return -1;
    }
    
    int total_files = 0;
    int total_dirs = 0;
    int success_count = 0;
    off_t original_size = file_size;
    
    printf("开始解压: %s\n", zip_filename);
    printf("输出目录: %s\n", output_directory);
    printf("空间优化: 解压后将删除原始ZIP中的对应数据\n");
    printf("文件格式: 基于实际压缩方法处理，不依赖文件名后缀\n");
    // 初始一次存储占用记录（若存在历史残留new临时文件，也计入）
    log_storage_usage(zip_filename, temp_filename, new_temp_filename);
    // 然后清理可能的历史残留new临时文件
    if (file_exists(new_temp_filename)) {
        delete_path(new_temp_filename);
    }
    
    // 遍历ZIP文件中的所有条目
    size_t pending_trim = 0; // 累计到阈值再裁剪
    while (1) {
        local_file_header_t header;
        char *filename = NULL;

        // 保存当前位置
        off_t current_pos = lseek(zip_fd, 0, SEEK_CUR);
        if (current_pos >= file_size) break;

        // 解析文件头
        int parse_result = parse_local_file_header(zip_fd, &header, &filename);
        if (parse_result != 0) {
            if (parse_result == -2) {
                // 不是有效的签名，向前扫描，带死循环保护
                int scan_limit = 1024 * 1024 * 20; // 最多扫描20MB
                int scan_count = 0;
                int found = 0;
                unsigned char buf[4];
                while (scan_count < scan_limit) {
                    ssize_t n = read(zip_fd, buf, 4);
                    if (n < 4) break;
                    uint32_t sig = read_le32(buf);
                    if (sig == LOCAL_FILE_HEADER_SIGNATURE) {
                        // 找到合法头，回退到头部
                        lseek(zip_fd, -4, SEEK_CUR);
                        found = 1;
                        break;
                    } else {
                        lseek(zip_fd, -3, SEEK_CUR); // 向前1字节
                        scan_count++;
                        if (scan_count % (1024*1024) == 0) {
                            printf("警告：正在扫描下一个local file header，已扫描%d MB...\n", scan_count/(1024*1024));
                        }
                    }
                }
                if (!found) {
                    fprintf(stderr, "未能在临时文件中找到下一个有效local file header，临时文件已损坏或流对齐丢失，建议删除 %s 重新解压！\n", temp_filename);
                    break;
                }
                continue;
            }
            break;
        }
        
        // 检查是否为目录（基于文件名）
        int is_directory = is_directory_entry(filename);
        uint64_t eff_comp_size = (header.compressed_size == 0xFFFFFFFFu && header.zip64_compressed_size)
                                   ? header.zip64_compressed_size : header.compressed_size;
        uint64_t eff_uncomp_size = (header.uncompressed_size == 0xFFFFFFFFu && header.zip64_uncompressed_size)
                                   ? header.zip64_uncompressed_size : header.uncompressed_size;
        int has_unknown_sizes = (header.compressed_size == 0xFFFFFFFFu && header.zip64_compressed_size == 0) ||
                                (header.uncompressed_size == 0xFFFFFFFFu && header.zip64_uncompressed_size == 0);
        
        printf("处理: %s (%s, 压缩大小: %u, 未压缩大小: %u, 压缩方法: %u)\n",
               filename, is_directory ? "目录" : "文件",
               header.compressed_size, header.uncompressed_size, header.compression_method);
        if (header.flags & 0x0001) {
            printf("提示: 条目已加密，当前不支持解密，跳过解压尝试\n");
        }
        
        // 构建输出路径
        char *output_path = build_output_path(filename);
        if (!output_path) {
            fprintf(stderr, "内存分配失败: %s\n", filename);
            free(filename);
            continue;
        }
        
        if (is_directory) {
            // 创建目录
            if (create_directory_recursive(output_path) == 0) {
                total_dirs++;
                success_count++;
                printf("创建目录成功: %s\n", output_path);
            } else {
                fprintf(stderr, "创建目录失败: %s\n", output_path);
            }
            
            // 目录没有数据，但仍需裁剪已处理的头部
            free(filename);
            free(output_path);

            // 计算已处理的数据量（仅头部）并累计
            pending_trim += (size_t)(30 + header.filename_length + header.extra_field_length);
            if (pending_trim >= trim_threshold_bytes || !fast_mode) {
                // 执行批量裁剪
                close(zip_fd);
                int collapsed = 0;
                int temp_fd_rw = open(temp_filename, O_RDWR);
                if (temp_fd_rw >= 0) {
                    if (fallocate(temp_fd_rw, FALLOC_FL_COLLAPSE_RANGE, 0, (off_t)pending_trim) == 0) collapsed = 1;
                    close(temp_fd_rw);
                }
                if (!collapsed) {
                    if (in_place_compact(temp_filename, (off_t)pending_trim) != 0) {
                        if (copy_remaining_data(temp_filename, new_temp_filename, (off_t)pending_trim) != 0) {
                            fprintf(stderr, "更新临时文件失败\n");
                            delete_path(new_temp_filename);
                            delete_path(temp_filename);
                            return -1;
                        }
                        if (!fast_mode) log_storage_usage(zip_filename, temp_filename, new_temp_filename);
                        delete_path(temp_filename);
                        if (rename(new_temp_filename, temp_filename) != 0) {
                            perror("重命名临时文件失败");
                            delete_path(new_temp_filename);
                            delete_path(temp_filename);
                            return -1;
                        }
                    }
                }
                zip_fd = open(temp_filename, O_RDONLY);
                if (zip_fd < 0) { perror("无法重新打开临时文件"); delete_path(temp_filename); return -1; }
                file_size = lseek(zip_fd, 0, SEEK_END);
                if (file_size <= 0) { close(zip_fd); break; }
                lseek(zip_fd, 0, SEEK_SET);
                pending_trim = 0;
                if (!fast_mode) {
                    off_t tmp_sz = get_file_size(temp_filename);
                    if (tmp_sz > 0) printf("当前原始ZIP剩余大小: %jd 字节\n", (intmax_t)tmp_sz);
                    log_storage_usage(zip_filename, temp_filename, NULL);
                }
            }
            continue;
        }
        
        // 处理文件：先创建父目录
        char *filename_copy = strdup(output_path);
        if (filename_copy) {
            char *dir_part = dirname(filename_copy);
            if (strcmp(dir_part, ".") != 0) {
                create_directory_recursive(dir_part);
            }
            free(filename_copy);
        }
        
int skip_write = 0;
        const char *target_path = output_path;
        struct stat outst;
        if (stat(output_path, &outst) == 0) {
            if (S_ISDIR(outst.st_mode)) {
                skip_write = 1;
            } else if (S_ISREG(outst.st_mode)) {
                skip_write = 1;
            }
        }
        // 只传实际目标路径，skip_write为1时传 NULL 给 output_path
        uint32_t consumed = 0;
        uint32_t dd_len = 0;
        uint32_t pass_comp = (header.compressed_size == 0xFFFFFFFFu) ? 0u : (uint32_t)eff_comp_size;
        uint32_t pass_uncomp = (header.uncompressed_size == 0xFFFFFFFFu) ? 0u : (uint32_t)eff_uncomp_size;
        // 解压条目
        int file_result = inflate_file(zip_fd, skip_write ? NULL : target_path, pass_comp,
                                      pass_uncomp, header.compression_method, header.flags,
                                      &consumed, &dd_len, skip_write);

        if (file_result == 0) {
            total_files++;
            success_count++;
            printf("解压文件成功: %s\n", output_path);

            // 只在成功时才累计
            off_t data_len = (header.flags & 0x0008 || has_unknown_sizes) ? consumed : (off_t)eff_comp_size;
            off_t dd_part = (header.flags & 0x0008) ? dd_len : 0;
            off_t processed = 30 + header.filename_length + header.extra_field_length + data_len + dd_part;
            pending_trim += (size_t)processed;
        } else {
            fprintf(stderr, "解压文件失败: %s (错误代码: %d)\n", output_path, file_result);
            if (!skip_write) {
                delete_path(output_path);
            }
            // 失败条目不能累计 processed
        }

        free(output_path);
        free(filename);

        // 计算已处理的数据量（文件头 + 文件数据 + 可能的data descriptor）
        off_t data_len = (off_t)((header.flags & 0x0008) || has_unknown_sizes ? consumed : (off_t)eff_comp_size);
        off_t dd_part = (off_t)((header.flags & 0x0008) ? dd_len : 0);
        off_t processed = 30 + header.filename_length + header.extra_field_length + data_len + dd_part;
        
        // 累计裁剪（批量阈值触发）
        pending_trim += (size_t)processed;
        if (pending_trim >= trim_threshold_bytes || !fast_mode) {
            close(zip_fd);
            int collapsed = 0;
            int temp_fd_rw = open(temp_filename, O_RDWR);
            if (temp_fd_rw >= 0) {
                if (fallocate(temp_fd_rw, FALLOC_FL_COLLAPSE_RANGE, 0, (off_t)pending_trim) == 0) collapsed = 1;
                close(temp_fd_rw);
            }
            if (!collapsed) {
                if (in_place_compact(temp_filename, (off_t)pending_trim) != 0) {
                    if (copy_remaining_data(temp_filename, new_temp_filename, (off_t)pending_trim) != 0) {
                        fprintf(stderr, "更新临时文件失败\n");
                        delete_path(new_temp_filename);
                        delete_path(temp_filename);
                        return -1;
                    }
                    if (!fast_mode) log_storage_usage(zip_filename, temp_filename, new_temp_filename);
                    delete_path(temp_filename);
                    if (rename(new_temp_filename, temp_filename) != 0) {
                        perror("重命名临时文件失败");
                        delete_path(new_temp_filename);
                        delete_path(temp_filename);
                        return -1;
                    }
                }
            }
            zip_fd = open(temp_filename, O_RDONLY);
            if (zip_fd < 0) { perror("无法重新打开临时文件"); delete_path(temp_filename); return -1; }
            file_size = lseek(zip_fd, 0, SEEK_END);
            if (file_size <= 0) { close(zip_fd); break; }
            lseek(zip_fd, 0, SEEK_SET);
            pending_trim = 0;
            if (!fast_mode) {
                off_t tmp_sz = get_file_size(temp_filename);
                if (tmp_sz > 0) printf("当前原始ZIP剩余大小: %jd 字节\n", (intmax_t)tmp_sz);
                log_storage_usage(zip_filename, temp_filename, NULL);
            }
        }
    }
    
    close(zip_fd);
    
    // 清理临时文件（临时文件即为被裁剪后的原始文件副本）
    if (file_exists(temp_filename)) {
        delete_path(temp_filename);
    }
    
    printf("解压完成 - 文件: %d 个, 目录: %d 个, 成功: %d 个\n", 
           total_files, total_dirs, success_count);
    
    return (success_count > 0) ? 0 : -1;
}

// 显示使用说明
void print_usage(const char *program_name) {
    printf("用法: %s [选项] <zip文件>\n", program_name);
    printf("选项:\n");
    printf("  -o, --output DIR     指定输出目录 (默认: 当前目录)\n");
    printf("  -f, --fast           快速模式（更大缓冲、批量裁剪、减少日志）\n");
    printf("      --no-log         关闭存储占用日志输出\n");
    printf("      --trim-mb N      批量裁剪阈值(单位MB，默认64)\n");
    printf("  -h, --help           显示此帮助信息\n");
    printf("\n");
    printf("功能:\n");
    printf("  真正的空间高效ZIP解压工具，只占用一倍空间\n");
    printf("  基于实际压缩方法处理文件，不依赖文件名后缀\n");
    printf("  正确处理ZIP文件中的目录结构\n");
}

// 主函数
int main(int argc, char *argv[]) {
    int opt;
    struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"fast", no_argument, 0, 'f'},
        {"no-log", no_argument, 0, 1},
        {"trim-mb", required_argument, 0, 2},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    // 解析命令行参数
    while ((opt = getopt_long(argc, argv, "o:fh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'o':
                strncpy(output_directory, optarg, sizeof(output_directory) - 1);
                output_directory[sizeof(output_directory) - 1] = '\0';
                break;
            case 'f':
                fast_mode = 1;
                enable_usage_log = 0; // 快速模式默认关闭日志
                break;
            case 1: // --no-log
                enable_usage_log = 0;
                break;
            case 2: { // --trim-mb
                long mb = strtol(optarg, NULL, 10);
                if (mb > 0) trim_threshold_bytes = (size_t)mb * 1024 * 1024;
                break;
            }
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // 检查是否有足够的参数
    if (optind >= argc) {
        fprintf(stderr, "错误: 需要指定ZIP文件或目录\n");
        print_usage(argv[0]);
        return 1;
    }
    
    const char *input_path = argv[optind];

    // 打印解压目录信息
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("当前工作目录: %s\n", cwd);
    }
    printf("输出目录: %s\n", output_directory);

    // 如果输入为目录，则处理目录下的所有.zip文件（仅顶层）
    if (is_directory_path(input_path)) {
        DIR *dir = opendir(input_path);
        if (!dir) {
            perror("无法打开目录");
            return 1;
        }
        struct dirent *entry;
        int overall_ok = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            // 仅处理常规文件名以.zip结尾
            const char *name = entry->d_name;
            size_t len = strlen(name);
            if (len < 4) continue;
            if (strcasecmp(name + len - 4, ".zip") != 0) continue;

            char fullpath[MAX_FILENAME_LEN];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", input_path, name);
            if (!file_exists(fullpath)) continue;
            off_t fs = get_file_size(fullpath);
            if (fs <= 0) continue;

            if (space_efficient_unzip_v3(fullpath) == 0) {
                overall_ok = 1;
            }
        }
        closedir(dir);
        if (overall_ok) {
            printf("解压完成\n");
            return 0;
        } else {
            fprintf(stderr, "目录中未成功解压任何ZIP\n");
            return 1;
        }
    }

    // 输入为文件
    int orig_exists = file_exists(input_path);
    char resume_tmp[MAX_FILENAME_LEN + strlen(TEMP_SUFFIX) + 1];
    snprintf(resume_tmp, sizeof(resume_tmp), "%s%s", input_path, TEMP_SUFFIX);
    int tmp_exists = file_exists(resume_tmp);

    if (!orig_exists && !tmp_exists) {
        fprintf(stderr, "错误: 文件不存在 - %s\n", input_path);
        return 1;
    }
    if (!orig_exists && tmp_exists) {
        printf("检测到临时文件，继续恢复: %s\n", resume_tmp);
    }

    // 文件大小校验：若原始不存在，则检查临时文件大小
    off_t file_size = orig_exists ? get_file_size(input_path) : get_file_size(resume_tmp);
    if (file_size <= 0) {
        fprintf(stderr, "错误: 无效的文件或文件为空 - %s\n", orig_exists ? input_path : resume_tmp);
        return 1;
    }

    if (space_efficient_unzip_v3(input_path) == 0) {
        printf("解压完成\n");
        return 0;
    } else {
        fprintf(stderr, "解压失败\n");
        return 1;
    }
}
