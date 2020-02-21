WITH
arraySort(x->x.2,groupUniqArray((p1.reply_ip, p2.reply_ip, snapshot))) as flow_reply_ip_snapshots,
arrayMap((x->(x.1,x.2)), flow_reply_ip_snapshots) as reply_ips,
length(reply_ips) as n_response,
arrayDistinct(reply_ips) as dynamics,
length(dynamics) as n_dynamics,
arrayElement(reply_ips, 1) as edge


SELECT distinct(src_ip, dst_ip, dst_port, ttl),
n_response,
n_dynamics,
edge

-- ips_per_snapshot_1,
-- ips_per_snapshot_2,
-- reply_ips_array,
-- flow_ids_array,
-- max(dst_port) -- In case we have to remap
FROM
(SELECT *
FROM   versioned_probes
WHERE dst_ip BETWEEN 10000000 AND 20000000 AND ttl >= 3
) as p1
LEFT JOIN
(SELECT *
FROM   versioned_probes
WHERE dst_ip BETWEEN 10000000 AND 20000000 AND ttl >= 3
) as p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port=p2.src_port) AND(p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND p1.snapshot = p2.snapshot AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)

WHERE dst_ip NOT IN
(
(SELECT distinct(dst_ip) FROM
(SELECT
        src_ip,
        dst_ip,
        ttl,
        COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
        COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt
    FROM   versioned_probes
    WHERE dst_ip BETWEEN 10000000 AND 20000000 AND ttl >= 3
    GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round, snapshot)
    HAVING (cnt > 2)  OR (n_ips_per_ttl_flow > 1)
--     ORDER BY (src_ip, dst_ip, ttl) ASC
)
)
)

GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
LIMIT 10
-- ORDER BY (src_ip, dst_ip, ttl, src_port, dst_port)


-- Extracts all the diamonds from the DB.
WITH groupUniqArray((reply_ip, ttl, dst_ip, dst_port)) as replies,
arraySort(x->x.2, replies) as sorted_replies,
arrayMap(x->x.1, sorted_replies) as ips,
arrayMap(x->x.2, sorted_replies) as ttls,
arrayMap(x->x.3, sorted_replies) as dst_ports
SELECT dst_prefix, ips,
ttls,
dst_ports
FROM destination_versioned_probes
WHERE dst_ip > 0 AND dst_ip <= 20000000
AND src_port = 24000 AND dst_port >= 33434
AND dst_ip NOT IN
(
(SELECT distinct(dst_ip) FROM
(SELECT
        src_ip,
        dst_ip,
        ttl,
        COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
        COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt
    FROM   versioned_probes
    WHERE dst_ip BETWEEN 0 AND 20000000
    GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round, snapshot)
    HAVING (cnt > 2)  OR (n_ips_per_ttl_flow > 1)
--     ORDER BY (src_ip, dst_ip, ttl) ASC
)
)
)
GROUP BY src_ip, dst_prefix
LIMIT 100


