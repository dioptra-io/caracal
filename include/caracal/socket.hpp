#pragma once

#include <spdlog/spdlog.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <system_error>
#include <vector>

namespace caracal {

class Socket {
 public:
  Socket(int domain, int type, int protocol) {
    socket_ = check(socket(domain, type, protocol));
  }

  Socket(const Socket &) = delete;
  Socket(const Socket &&) = delete;

  ~Socket() { close(socket_); }

  template <typename T>
  void bind(const T *addr) const {
    check(::bind(socket_, reinterpret_cast<const sockaddr *>(addr), sizeof(T)));
  }

  void send(const void *buf, size_t len, int flags) const {
    check(::send(socket_, buf, len, flags));
  }

  template <typename T>
  void sendto(const void *buf, size_t len, int flags,
              const T *dest_addr) const {
    check(::sendto(socket_, buf, len, flags,
                   reinterpret_cast<const sockaddr *>(dest_addr), sizeof(T)));
  }

  [[nodiscard]] void *mmap(void *addr, size_t len, int prot, int flags,
                           off_t offset) const {
    auto ptr = ::mmap(addr, len, prot, flags, socket_, offset);
    if (ptr == MAP_FAILED) {
      throw std::system_error(errno, std::generic_category());
    }
    return ptr;
  }

  void munmap(void *addr, size_t len) const { check(::munmap(addr, len)); }

  template <typename T>
  void set(int level, int option_name, const T *value) const {
    check(setsockopt(socket_, level, option_name, value, sizeof(T)));
  }

  void set(int level, int option_name, int option_value) const {
    check(setsockopt(socket_, level, option_name, &option_value,
                     sizeof(option_value)));
  }

 private:
  int socket_;

  static ssize_t check(ssize_t val) {
    if (val < 0) {
      throw std::system_error(errno, std::generic_category());
    }
    return val;
  }
};

}  // namespace caracal
