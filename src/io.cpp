#include <zstd.h>

#include <caracal/io.hpp>
#include <fstream>
#include <stdexcept>
#include <string>

namespace caracal::IO {

ZstdWriter::ZstdWriter()
    : file_{},
      out_buffer_{},
      out_buffer_s_{out_buffer_.data(), out_buffer_.size(), 0} {
  cctx_ = ZSTD_createCCtx();
  if (!cctx_) {
    throw std::runtime_error{"Unable to create zstd context"};
  }
}

ZstdWriter::~ZstdWriter() {
  close();
  ZSTD_freeCCtx(cctx_);
}

void ZstdWriter::open(const std::string& filename) {
  file_.open(filename, std::ios::out | std::ios::binary);
}

void ZstdWriter::close() {
  flush_frame();
  file_.close();
}

void ZstdWriter::write(const std::string& s) {
  ZSTD_inBuffer_s in_buffer_s{s.data(), s.size(), 0};
  // Try to compress in a single call.
  check(ZSTD_compressStream2(cctx_, &out_buffer_s_, &in_buffer_s,
                             ZSTD_e_continue));
  // Flush output buffer to file if there are remaining input data.
  while (in_buffer_s.pos < in_buffer_s.size) {
    flush_out_buffer();
    check(ZSTD_compressStream2(cctx_, &out_buffer_s_, &in_buffer_s,
                               ZSTD_e_continue));
  }
}

size_t ZstdWriter::check(size_t ret) {
  if (ZSTD_isError(ret)) {
    throw std::runtime_error{"unexpected zstd exception: " +
                             std::to_string(ret)};
  }
  return ret;
}

void ZstdWriter::flush_frame() {
  ZSTD_inBuffer_s in_buffer_s{nullptr, 0, 0};
  size_t remaining = 1;
  while (remaining != 0) {
    remaining = check(
        ZSTD_compressStream2(cctx_, &out_buffer_s_, &in_buffer_s, ZSTD_e_end));
  }
  flush_out_buffer();
}

void ZstdWriter::flush_out_buffer() {
  file_.write(out_buffer_.data(), out_buffer_s_.pos);
  out_buffer_s_.pos = 0;
}

}  // namespace caracal::IO
