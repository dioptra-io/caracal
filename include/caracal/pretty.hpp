#pragma once

#include <arpa/inet.h>
#include <pcap.h>

#include <ostream>

std::ostream& operator<<(std::ostream& os, in_addr const& v);

std::ostream& operator<<(std::ostream& os, in6_addr const& v);

std::ostream& operator<<(std::ostream& os, sockaddr_in const& v);

std::ostream& operator<<(std::ostream& os, sockaddr_in6 const& v);

std::ostream& operator<<(std::ostream& os, pcap_stat const& v);
