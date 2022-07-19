# Usage

## Example

Probe Google DNS servers at TTL 32:
```csv title="probes.txt"
8.8.8.8,24000,33434,32,icmp
8.8.4.4,24000,33434,32,icmp
2001:4860:4860::8888,24000,33434,32,icmp
2001:4860:4860::8844,24000,33434,32,icmp
```
```bash
# Standard input/output
cat probes.txt | caracal > replies.csv
# File input/output
caracal -i probes.txt -o replies.csv
```

## Input format

Caracal reads probe specifications from the standard input or, if specified with `-i/--input-file`, from a file with one probe per line.
If the input file is compressed with with [zstd](https://facebook.github.io/zstd/) and ends with `.zst` it will be decompressed on-the-fly.

The input format is:
```csv
dst_addr,src_port,dst_port,ttl,protocol
```

- `dst_addr` can be an IPv4 address in dotted notation (e.g. `8.8.8.8`), an IPv4-mapped IPv6 address (e.g. `::ffff:8.8.8.8`)
  or an IPv6 address (e.g. `2001:4860:4860::8888`).
- `src_port` and `dst_port` are integer values between 0 and 65535. For UDP probes, the ports are encoded directly in the UDP header. For ICMP probes, the source port is encoded in the ICMP checksum (which varies the flow-id).
- `protocol` can be `icmp`, `icmp6` or `udp`.

## Output format

Caracal outputs the replies in CSV format on the standard output or, if specified with `-o/--output-file-csv`, to a file with one reply per line.
If the file name ends with `.zst` the output will be compressed on-the-fly with zstd.

In addition, if `--output-file-pcap` is specified, the raw captured frames will be written to the specified file in PCAP format.  
Log messages are printed on the standard error stream.

The output format is:
```csv
capture_timestamp,probe_protocol,probe_src_addr,probe_dst_addr,probe_src_port,probe_dst_port,probe_ttl,quoted_ttl,reply_src_addr,reply_protocol,reply_icmp_type,reply_icmp_code,reply_ttl,reply_size,reply_mpls_labels,rtt,round
```

- `capture_timestamp` is a 64-bit integer representing the capture time in microseconds.
- `probe_protocol` is an 8-bit integer representing the IP protocol number of the probe packet.
- `probe_src_addr` is an IPv6 string representing the source address of the probe packet.
- `probe_dst_addr` is an IPv6 string representing the destination address of the probe packet.
- `probe_src_port` is a 16-bit integer representing the source port of the probe packet (for UDP), or the ICMP checksum (for ICMP).
- `probe_dst_port` is a 16-bit integer representing the destination port of the probe packet (for UDP).
- `probe_ttl` is an 8-bit integer representing the TTL of the probe packet.
- `quoted_ttl` is an 8-bit integer representing the TTL of the probe packet quoted in the ICMP reply.
- `reply_src_addr` is an IPv6 string representing the source address of the reply packet.
- `reply_protocol` is an 8-bit integer representing the IP protocol number of the reply packet.
- `reply_icmp_type` is an 8-bit integer representing the ICMP type of the reply packet.
- `reply_icmp_code` is an 8-bit integer representing the ICMP code of the reply packet.
- `reply_ttl` is an 8-bit integer representing the TTL of the reply packet.
- `reply_size` is a 16-bit integer representing the size of the reply packet
- `reply_mpls_labels` is an array of (label, exp, bottom-of-stack, ttl) tuples representing the MPLS labels contained in the ICMP reply.
- `rtt` is a 16-bit integer representing the estimated round-trip time in tenth of milliseconds.
- `round` is an arbitrary string set with `--meta-round` (default `1`).

## Integration with standard tools

It is easy to integrate caracal with standard UNIX tools by taking advantage of the standard input/output.
For example, to store the replies in a SQLite database:
```bash
echo "8.8.8.8,24000,33434,64,icmp" | caracal | sqlite3 caracal.db ".import --csv /dev/stdin replies"
sqlite3 -header caracal.db "SELECT * FROM replies"
# capture_timestamp|probe_protocol|probe_src_addr|probe_dst_addr|probe_src_port|probe_dst_port|probe_ttl|quoted_ttl|reply_src_addr|reply_protocol|reply_icmp_type|reply_icmp_code|reply_ttl|reply_size|reply_mpls_labels|rtt|round
# 1638618261|1|::ffff:10.17.0.137|::|24000|0|64|0|::ffff:8.8.8.8|1|0|0|107|94|[]|564|1
```

## Checksum

Caracal encodes the following checksum in the ID field of the IP header:
```c++
ip_checksum(caracal_id, dst_addr, src_port, ttl)
```
This allows caracal to check that the reply it gets corresponds (excluding checksum collisions) to valid probes.

By default, replies for which the checksum in the ID field is invalid are dropped, this can be overridden with the
`--no-integrity-check` flag.
Furthermore, the `caracal_id` value can be changed with the `--caracal-id` option.

Invalid replies are never dropped from the PCAP file (`--output-file-pcap`), which can be useful for debugging.
