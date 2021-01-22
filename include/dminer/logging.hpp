#pragma once

#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <string>

/// Boost.Log is not lazy, i.e. the stream is evaluated before filtering the
/// message depending on the log level. To avoid this, the LOG macro checks the
/// log level before evaluating the stream.
#define LOG(severity, expr)                         \
  if (boost::log::trivial::severity >= log_level) { \
    BOOST_LOG_TRIVIAL(severity) << expr;            \
  }

namespace expr = boost::log::expressions;
namespace logging = boost::log;
namespace keywords = boost::log::keywords;

namespace dminer {

static boost::log::trivial::severity_level log_level;

void configure_logging(const std::string& level) {
  logging::add_common_attributes();
  logging::add_console_log(
      std::cerr,
      keywords::format =
          (expr::stream << expr::format_date_time<boost::posix_time::ptime>(
                               "TimeStamp", "%Y/%m/%d %H:%M:%S.%f")
                        << " (" << logging::trivial::severity << ") "
                        << expr::message));

  if (level == "trace") {
    log_level = boost::log::trivial::trace;
  } else if (level == "debug") {
    log_level = boost::log::trivial::debug;
  } else if (level == "info") {
    log_level = boost::log::trivial::info;
  } else if (level == "warning") {
    log_level = boost::log::trivial::warning;
  } else if (level == "error") {
    log_level = boost::log::trivial::error;
  } else if (level == "fatal") {
    log_level = boost::log::trivial::fatal;
  } else {
    throw std::invalid_argument("Invalid log level: " + level);
  }

  // We do not make use of Boost.Log filtering facilities,
  // instead we rely on the LOG macro, for performance reasons.
  // logging::core::get()->set_filter(logging::trivial::severity >= log_level);
}

}  // namespace dminer
