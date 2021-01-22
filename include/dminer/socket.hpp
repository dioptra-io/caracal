#pragma once

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <system_error>
#include <vector>

namespace dminer {

template <typename T>
void assert_sockaddr_in(const T *) {
  static_assert(std::is_same<T, sockaddr_in>::value ||
                    std::is_same<T, sockaddr_in6>::value,
                "addr must be sockaddr_in or sockaddr_in6");
}

class Socket {
 public:
  Socket(int domain, int type, int protocol) {
    socket_ = check(socket(domain, type, protocol));
  }

  Socket(const Socket &) = delete;
  Socket(const Socket &&s) = delete;

  ~Socket() { close(socket_); }

  template <typename T>
  void bind(const T *addr) const {
    assert_sockaddr_in(addr);
    check(::bind(socket_, reinterpret_cast<const sockaddr *>(addr), sizeof(T)));
  }

  template <typename T>
  void sendto(const void *buf, size_t len, int flags,
              const T *dest_addr) const {
    assert_sockaddr_in(dest_addr);
    check(::sendto(socket_, buf, len, flags,
                   reinterpret_cast<const sockaddr *>(dest_addr), sizeof(T)));
  }

  void set(int level, int option_name, int option_value) const {
    check(setsockopt(socket_, level, option_name, &option_value,
                     sizeof(option_value)));
  }

 private:
  int socket_;

  static int check(ssize_t val) {
    if (val < 0) {
      throw std::system_error(errno, std::generic_category());
    }
    return val;
  }
};

}  // namespace dminer
