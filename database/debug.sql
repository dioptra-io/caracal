WITH groupUniqArray((reply_ip, dst_ip, dst_port)) as replies,
arrayMap(x->x.1, replies) as ips,
arrayMap(x->x.2, replies) as dst_ips,
arrayMap(x->x.3, replies) as dst_ports
SELECT src_ip, dst_prefix, ttl, snapshot,ips,
dst_ips,
dst_ports FROM heartbeat.probes
WHERE dst_ip > 20971519 AND dst_ip <= 25165823 AND (dst_ip NOT IN
(
    SELECT DISTINCT dst_ip
    FROM
    (
        SELECT
            src_ip,
            dst_ip,
            ttl,
            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
            COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt
            FROM heartbeat.probes
        WHERE dst_ip > 20971519 AND dst_ip <= 25165823        GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round, snapshot)
        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)
    )
))
GROUP BY (src_ip, dst_prefix, ttl, snapshot)ORDER BY (src_ip, dst_prefix, ttl, snapshot) ASC