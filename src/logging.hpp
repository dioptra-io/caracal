#pragma once

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <iostream>
#include <string>

namespace expr = boost::log::expressions;
namespace logging = boost::log;
namespace keywords = boost::log::keywords;

void configure_logging(const std::string log_level) {
  logging::add_common_attributes();
  logging::add_console_log(
      std::cerr,
      keywords::format =
          (expr::stream << expr::format_date_time<boost::posix_time::ptime>(
                               "TimeStamp", "%Y/%m/%d %H:%M:%S.%f")
                        << " (" << logging::trivial::severity << ") "
                        << expr::message));

  auto level = boost::log::trivial::trace;
  if (log_level == "trace") {
    level = boost::log::trivial::trace;
  } else if (log_level == "debug") {
    level = boost::log::trivial::debug;
  } else if (log_level == "info") {
    level = boost::log::trivial::info;
  } else if (log_level == "warning") {
    level = boost::log::trivial::warning;
  } else if (log_level == "error") {
    level = boost::log::trivial::error;
  } else if (log_level == "fatal") {
    level = boost::log::trivial::fatal;
  } else {
    throw std::invalid_argument("Invalid log level: " + log_level);
  }

  logging::core::get()->set_filter(logging::trivial::severity >= level);
}
