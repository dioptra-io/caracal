#pragma once

#include <zstd.h>

#include <array>
#include <fstream>
#include <string>

namespace caracal::IO {

/// Write zstd-compressed data to file.
class ZstdWriter {
 public:
  ZstdWriter();
  ZstdWriter(const ZstdWriter&) = delete;
  ZstdWriter(const ZstdWriter&&) = delete;
  ~ZstdWriter();

  /// Open the output file `filename`.
  void open(const std::string& filename);

  /// Flush the compressed buffer to the disk and close the output file.
  void close();

  /// Compress the string `s`.
  /// If the compressed buffer is full, it will be flushed to the disk.
  void write(const std::string& s);

 private:
  std::ofstream file_;
  std::array<char, 1048576> out_buffer_;
  ZSTD_outBuffer_s out_buffer_s_;
  ZSTD_CCtx_s* cctx_;

  /// Throw an exception if `ret` is a zstd error.
  static size_t check(size_t ret);
  /// End the zstd frame and write any remaining data to the output file.
  void flush_frame();
  /// Write the zstd buffer to the output file and reset its position to 0.
  void flush_out_buffer();
};

}  // namespace caracal::IO
