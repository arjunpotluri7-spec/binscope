#include "io.hpp"

#include <cerrno>
#include <cstring>
#include <string>

#if defined(_WIN32)
#include <filesystem>
#include <fstream>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace binscope::cli {

namespace {

std::string os_error(int code) {
    // strerror is not guaranteed thread-safe, but the CLI is single-threaded.
    return std::strerror(code);  // NOLINT(concurrency-mt-unsafe)
}

}  // namespace

#if defined(_WIN32)

Result<std::vector<std::uint8_t>> read_input(const std::string& path, std::uint64_t max_size,
                                             bool follow_symlinks) {
    namespace fs = std::filesystem;
    std::error_code ec;
    const auto link = fs::symlink_status(path, ec);
    if (ec) {
        return make_error(path + ": " + ec.message());
    }
    if (fs::is_symlink(link) && !follow_symlinks) {
        return make_error(path + ": is a symbolic link (pass --follow-symlinks to read it)");
    }
    if (!fs::is_regular_file(fs::status(path, ec))) {
        return make_error(path + ": not a regular file");
    }
    const auto size = fs::file_size(path, ec);
    if (ec) {
        return make_error(path + ": " + ec.message());
    }
    if (size > max_size) {
        return make_error(path + ": file is " + std::to_string(size) +
                          " bytes, larger than the limit of " + std::to_string(max_size) +
                          " bytes (see --max-size-mib)");
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return make_error(path + ": cannot open file");
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
    data.resize(static_cast<std::size_t>(in.gcount()));
    return data;
}

Result<bool> write_output(const std::string& path, const std::string& content, bool force) {
    namespace fs = std::filesystem;
    std::error_code ec;
    const auto st = fs::symlink_status(path, ec);
    if (!ec && fs::exists(st)) {
        if (fs::is_symlink(st)) {
            return make_error(path + ": refusing to write through a symbolic link");
        }
        if (!force) {
            return make_error(path + ": already exists (pass --force to overwrite)");
        }
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return make_error(path + ": cannot open for writing");
    }
    out << content;
    if (!out) {
        return make_error(path + ": write failed");
    }
    return true;
}

#else

Result<std::vector<std::uint8_t>> read_input(const std::string& path, std::uint64_t max_size,
                                             bool follow_symlinks) {
    struct stat link_info{};
    if (::lstat(path.c_str(), &link_info) != 0) {
        return make_error(path + ": " + os_error(errno));
    }
    if (S_ISLNK(link_info.st_mode) && !follow_symlinks) {
        return make_error(path + ": is a symbolic link (pass --follow-symlinks to read it)");
    }
    int flags = O_RDONLY | O_CLOEXEC;
#if defined(O_NONBLOCK)
    flags |= O_NONBLOCK;  // never block opening a FIFO that slipped past the checks
#endif
    if (!follow_symlinks) {
        flags |= O_NOFOLLOW;
    }
    const int fd = ::open(path.c_str(), flags);  // NOLINT(cppcoreguidelines-pro-type-vararg)
    if (fd < 0) {
        return make_error(path + ": " + os_error(errno));
    }
    struct stat info{};
    if (::fstat(fd, &info) != 0) {
        const int code = errno;
        ::close(fd);
        return make_error(path + ": " + os_error(code));
    }
    if (!S_ISREG(info.st_mode)) {
        ::close(fd);
        return make_error(path + ": not a regular file");
    }
    const auto size = static_cast<std::uint64_t>(info.st_size);
    if (size > max_size) {
        ::close(fd);
        return make_error(path + ": file is " + std::to_string(size) +
                          " bytes, larger than the limit of " + std::to_string(max_size) +
                          " bytes (see --max-size-mib)");
    }
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::read(fd, data.data() + done, data.size() - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int code = errno;
            ::close(fd);
            return make_error(path + ": read failed: " + os_error(code));
        }
        if (n == 0) {
            break;  // file shrank while reading; analyse what is there
        }
        done += static_cast<std::size_t>(n);
    }
    ::close(fd);
    data.resize(done);
    return data;
}

Result<bool> write_output(const std::string& path, const std::string& content, bool force) {
    int flags = O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW;
    flags |= force ? O_TRUNC : O_EXCL;
    const int fd = ::open(path.c_str(), flags, 0600);  // NOLINT(cppcoreguidelines-pro-type-vararg)
    if (fd < 0) {
        const int code = errno;
        if (code == EEXIST) {
            return make_error(path + ": already exists (pass --force to overwrite)");
        }
        if (code == ELOOP) {
            return make_error(path + ": refusing to write through a symbolic link");
        }
        return make_error(path + ": cannot open for writing: " + os_error(code));
    }
    ::fchmod(fd, 0600);
    std::size_t done = 0;
    while (done < content.size()) {
        const ssize_t n = ::write(fd, content.data() + done, content.size() - done);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int code = errno;
            ::close(fd);
            return make_error(path + ": write failed: " + os_error(code));
        }
        done += static_cast<std::size_t>(n);
    }
    if (::close(fd) != 0) {
        return make_error(path + ": write failed: " + os_error(errno));
    }
    return true;
}

#endif

}  // namespace binscope::cli
