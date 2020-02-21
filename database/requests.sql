-- Create probes table
CREATE TABLE probes_mda_yarrp_snapshot_1(src_ip UInt32, dst_prefix UInt32, dst_ip UInt32, reply_ip UInt32, src_port UInt16, dst_port UInt16, ttl UInt8, type UInt8, code UInt8, round UInt32, Sign Int8, snapshot UInt16) ENGINE=VersionedCollapsingMergeTree(Sign, snapshot) ORDER BY (src_ip, dst_prefix, dst_ip, ttl, src_port, dst_port, snapshot)

CREATE TABLE rtt_probes(src_ip UInt32, dst_prefix UInt32, dst_ip UInt32, reply_ip UInt32, src_port UInt16, dst_port UInt16, ttl UInt8, type UInt8, code UInt8, rtt Float64, reply_ttl UInt8, reply_size UInt16, round UInt32, snapshot UInt16) ENGINE=MergeTree() ORDER BY (src_ip, dst_prefix, dst_ip, ttl, src_port, dst_port, snapshot)

CREATE TABLE probes_sent(src_ip UInt32, dst_ip UInt32, src_port UInt16, dst_port UInt16, ttl UInt8) ENGINE=MergeTree() ORDER BY (src_ip, dst_ip, src_port, dst_port, ttl)

CREATE TABLE dynamics (src_ip UInt32, dst_prefix UInt32,  dst_ip UInt32, ttl UInt8, reply_ip UInt32, timestamp UInt64, round UInt16) ENGINE=MergeTree() ORDER BY (src_ip, dst_prefix, dst_ip, ttl)

CREATE TABLE nks (epsilon Float32, nks Array(UInt32)) ENGINE=MergeTree() ORDER BY epsilon

-- Delete old records
ALTER TABLE rtt_probes DELETE WHERE 1=1

CREATE TABLE probes_validation_d_miner(src_ip UInt32, dst_prefix UInt32, dst_ip UInt32, reply_ip UInt32, src_port UInt16, dst_port UInt16, ttl UInt8, type UInt8, code UInt8, round UInt32, Sign Int8, snapshot UInt16) ENGINE=VersionedCollapsingMergeTree(Sign, snapshot) ORDER BY (src_ip, dst_prefix, dst_ip, ttl, src_port, dst_port, snapshot)

-- Export data into native format
clickhouse-client --max_threads="1"  --query="select * from heartbeat.probes_ple_evaluation  WHERE src_ip=2689654055 FORMAT Native "  > resources/planet-lab-node2.netgroup.uniroma2.it
clickhouse-client --max_threads="1"  --query="select * from heartbeat.probes_ple_evaluation  WHERE src_ip=2162714569 FORMAT Native "  > resources/planetlab1.xeno.cl.cam.ac.uk
nohup cat resources/cse-yellow.cse.chalmers.se | clickhouse-client --query="INSERT INTO heartbeat.probes_cse_yellow_cse_chalmers_se FORMAT Native" &
nohup cat resources/icnalplabs1.epfl.ch | clickhouse-client --query="INSERT INTO heartbeat.probes_icnalplabs1_epfl_ch FORMAT Native" &
nohup cat resources/planetlab1.xeno.cl.cam.ac.uk | clickhouse-client --query="INSERT INTO heartbeat.probes_planetlab1_xeno_cl_cam_ac_uk FORMAT Native" &
nohup cat resources/kulcha.mimuw.edu.pl | clickhouse-client --query="INSERT INTO heartbeat.probes_kulcha_mimuw_edu_pl FORMAT Native" &
nohup cat resources/planet-lab-node2.netgroup.uniroma2.it | clickhouse-client --query="INSERT INTO heartbeat.probes_planet_lab_node2_netgroup_uniroma2_it FORMAT Native" &
nohup cat resources/pl2.prakinf.tu-ilmenau.de | clickhouse-client --query="INSERT INTO heartbeat.probes_pl2_prakinf_tu_ilmenau_de FORMAT Native" &

nohup cat resources/mda_yarrp_snapshot_1 | clickhouse-client --query="INSERT INTO heartbeat.probes_mda_yarrp_snapshot_1 FORMAT Native" &
nohup cat resources/mda_yarrp_snapshot_2 | clickhouse-client --query="INSERT INTO heartbeat.probes_mda_yarrp_snapshot_2 FORMAT Native" &
nohup cat resources/mda_yarrp_snapshot_3 | clickhouse-client --query="INSERT INTO heartbeat.probes_mda_yarrp_snapshot_3 FORMAT Native" &

nohup cat  | clickhouse-client --query="INSERT INTO heartbeat.probes_sent FORMAT CSV" &

KILL QUERY WHERE query_id in (SELECT query_id from system.processes)

-- Find per packet and weird stuff
SELECT count(distinct(dst_ip)) FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, snapshot)
HAVING cnt > 2 OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
GROUP BY (src_ip, dst_ip)


-- Find the number of distinct IPs discovered filtering anomalies
select
snapshot, count(distinct(reply_ip))
from rate_limit_probes
WHERE dst_ip NOT IN
(SELECT dst_ip FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
-- COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT(src_ip, dst_ip, ttl, src_port, dst_port, snapshot) as cnt
FROM probes
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, snapshot)
HAVING cnt > 2 OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
GROUP BY (src_ip, dst_ip)
)
GROUP BY snapshot



-- Template request for tracenode granularity
SELECT distinct(reply_ip, src_ip, dst_ip, src_port, dst_port, ttl)
FROM
(SELECT *
FROM   probes
WHERE dst_ip >  200000000  AND dst_ip <=  300000000
)
WHERE dst_ip NOT IN
(
(SELECT dst_ip FROM
(SELECT
        src_ip,
        dst_ip,
        ttl,
        COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
        COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt,
        MAX(round) as max_round
    FROM   probes
    WHERE dst_ip >   200000000   AND dst_ip <=   300000000
    GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
    HAVING (cnt > 2) -- OR (n_ips_per_ttl_flow > 1)
    ORDER BY (src_ip, dst_ip, ttl) ASC
)
)
)

-- Template request for traceroute granularity

SELECT src_ip, dst_ip, ttl,
arrayMap((x->x[1]), groupUniqArray([reply_ip, dst_port])) as tracenodes
FROM
(SELECT *
FROM   probes
WHERE dst_ip >  200000000  AND dst_ip <=  300000000
)
WHERE dst_ip NOT IN
(
(SELECT dst_ip FROM
(SELECT
        src_ip,
        dst_ip,
        ttl,
        COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
        COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt,
        MAX(round) as max_round
    FROM   probes
    WHERE dst_ip >   2000000000   AND dst_ip <=   300000000
    GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
    HAVING (cnt > 2) -- OR (n_ips_per_ttl_flow > 1)
    ORDER BY (src_ip, dst_ip, ttl) ASC
)
)
)
GROUP BY (src_ip, dst_ip, ttl)


-- Find the number of distinct links between two consecutive ttls filtering anomalies
SELECT 
                                      src_ip, 
                                      dst_ip, 
                                      max(p1.dst_port), 
                                      ttl, 
                                      countDistinct((p1.reply_ip, p2.reply_ip)) AS n_links,
                                      max(p1.round)
                                  FROM 
                                  (
                                      SELECT *
                                      FROM   probes  
                                      WHERE dst_ip >  100000000  AND dst_ip <=  200000000
                                  ) AS p1 
                                  INNER JOIN 
                                  (
                                      SELECT *
                                      FROM   probes  
                                      WHERE dst_ip >   100000000   AND dst_ip <=   200000000
                                  ) AS p2 ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)
                                  WHERE dst_ip NOT IN
                                  (
                                      SELECT dst_ip FROM
                                      (
                                          SELECT src_ip, dst_ip, MAX(round) as max_round FROM probes
                                          WHERE dst_ip >   100000000   AND dst_ip <=   200000000
                                          GROUP BY (src_ip, dst_ip)
                                          HAVING max_round < 10
                                          ORDER BY (src_ip, dst_ip)
                                      )
                                  )
                                  AND dst_ip NOT IN(
                                      SELECT dst_ip
                                      FROM 
                                      (
                                          SELECT 
                                              src_ip, 
                                              dst_ip, 
                                              ttl, 
                                              COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow, 
                                              COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt, 
                                              MAX(round) as max_round 
                                          FROM   probes  
                                          WHERE dst_ip >   100000000   AND dst_ip <=   200000000
                                          GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
                                          HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)
                                          ORDER BY (src_ip, dst_ip, ttl) ASC
                                      ) 
                                      GROUP BY (src_ip, dst_ip)
                                  )
                                  GROUP BY (src_ip, dst_ip, ttl)
                                  HAVING n_links > 1
                                  ORDER BY 
                                      dst_ip ASC, 
                                      ttl ASC


-- Find the number of distinct links discovered filtering anomalies
SELECT count(distinct(p1.reply_ip, p2.reply_ip)) as n_links, p1.dst_ip, p1.ttl, p2.ttl  --, max(p2.dst_port), p1.src_port, p1.dst_port, p2.dst_port
FROM (
SELECT * FROM probes WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000
) as p1
INNER JOIN (SELECT * FROM probes WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000) as p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port=p2.src_port) AND(p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)
WHERE dst_ip not in
(SELECT distinct(dst_ip) FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes
WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 10000000
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round)
HAVING cnt > 2 OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
)
-- GROUP BY (src_ip, dst_ip)
-- )
GROUP BY (p1.dst_ip, p1.ttl, p2.ttl )
-- HAVING n_links < 2000 AND  n_links > 1500
ORDER BY dst_ip, ttl


-- Find the different tracelinks (src_ip, dst_ip, src_port, dst_port, ttl) that identify a link.`
SELECT distinct(p1.reply_ip, p2.reply_ip, p1.dst_ip, p1.ttl, p2.ttl , p1.src_port, p1.dst_port)
FROM (SELECT * FROM probes WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000) as p1
INNER JOIN (SELECT * FROM probes WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000) as p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port=p2.src_port) AND(p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)
WHERE dst_ip not in
(SELECT distinct(dst_ip) FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes
WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round)
HAVING cnt > 2 OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
)
-- GROUP BY (link)
-- GROUP BY (src_ip, dst_ip, p1.ttl, p2.ttl, p1.src_port, p1.dst_port)
-- ORDER BY n_tracelinks DESC
LIMIT 100




-- Find the number of traceroutes that have not stable flows
select count(distinct(dst_ip)) from
(select src_ip, dst_ip, ttl, src_port, dst_port, count(distinct(reply_ip)) as cnt from probes_pfring
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port) HAVING cnt > 1)


-- Find the number of probes with same flow id but not same reply IP
select count() from
(select src_ip, dst_ip, ttl, src_port, dst_port, count(distinct(reply_ip)) as cnt from probes_pfring
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port) HAVING cnt > 1)

-- Find the number of IPs discovered by one flow
select count(distinct(reply_ip)) from probes where dst_port = ?


-- Find the number of unique links

SELECT count(distinct(g)) as cnt
FROM (
SELECT p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port,
groupUniqArray([p1.reply_ip, p2.reply_ip]) as g,
COUNT(DISTINCT(p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, p2.ttl, p2.dst_port)) as u
FROM
(SELECT * from probes WHERE dst_ip < 2147483648)
AS p1
INNER JOIN
(SELECT * from probes WHERE dst_ip < 2147483648)
AS p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.dst_port = p2.dst_port) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)
GROUP BY (p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port) HAVING u = 1
) as u1


-- Find the number of nodes founds at each TTL. Do not remove anomalies
SELECT src_ip, dst_ip, ttl, count(distinct(reply_ip)) as cnt
FROM
probes_pfring WHERE dst_ip < 1073741824
GROUP BY (src_ip, dst_ip, ttl)
HAVING cnt > 6
ORDER BY (src_ip, dst_ip, ttl)

-- (1) Only take the probes that got a response with same flow id =  same reply ip. (Remove per packets and anomalies)
SELECT src_ip, dst_ip, ttl, dst_port,
groupUniqArray(reply_ip) as g,
COUNT(DISTINCT(src_ip, dst_ip, ttl, dst_port, reply_ip)) as u
FROM
(SELECT * from probes_pfring WHERE dst_ip < 1073741824)
GROUP BY (src_ip, dst_ip, ttl, dst_port)
HAVING u = 1
) as u1

-- Find the number of nodes found at each TTL.
SELECT u1.src_ip, u1.dst_ip, u1.ttl, arrayUniq(groupArrayArray(g)) as cnt
FROM ( -- (1)
SELECT src_ip, dst_ip, ttl, dst_port,
groupUniqArray(reply_ip) as g,
COUNT(DISTINCT(src_ip, dst_ip, ttl, dst_port, reply_ip)) as u
FROM
(SELECT * from probes_pfring_2_rounds WHERE dst_ip < 1073741824)
GROUP BY (src_ip, dst_ip, ttl, dst_port)
HAVING u = 1
) as u1
GROUP BY (u1.src_ip, u1.dst_ip, u1.ttl)
HAVING cnt > 6
ORDER BY cnt DESC
LIMIT 100

-- Find the number of traceroutes that do not overlap for a given ttl TODO
SELECT groupArrayArray(cnt) as g, groupUniqArray([src_ip, dst_ip])
FROM (
SELECT u1.src_ip, u1.dst_ip, u1.ttl, groupArrayArray(g) as cnt
FROM ( -- (1)
SELECT src_ip, dst_ip, ttl, dst_port,
groupUniqArray(reply_ip) as g,
COUNT(DISTINCT(src_ip, dst_ip, ttl, dst_port, reply_ip)) as u
FROM
(SELECT * from probes_pfring WHERE dst_ip < 107374182)--2147483648)
GROUP BY (src_ip, dst_ip, ttl, dst_port)
HAVING u = 1
) as u1
GROUP BY (u1.src_ip, u1.dst_ip, u1.ttl)
HAVING arrayUniq(cnt) > 1
)
GROUP BY ttl

-- Find 1 representant of all equivalent traceroute per IP reply

SELECT reply_ip, COUNT(DISTINCT (src_ip, dst_ip, ttl))
FROM probes_pfring2
GROUP BY reply_ip



-- Find the diamonds

select src_ip, dst_ip, ttl, count(distinct(reply_ip)) as cnt from probes
group by (src_ip, dst_ip, ttl) having cnt > 1
order by (src_ip, dst_ip, ttl)

-- Find traceroutes that contain a diamond
select distinct src_ip, dst_ip
from (select src_ip, dst_ip, ttl, count(distinct(reply_ip)) as cnt
      from probes
      group by (src_ip,dst_ip,ttl) having cnt > 1
      order by (src_ip,dst_ip,ttl))


-- Find the dynamics on nodes between 2 snapshots
SELECT COUNT(DISTINCT(src_ip, dst_ip)) FROM
(
SELECT src_ip, dst_ip, ttl, groupUniqArray(j1.ip_per_flow_per_ttl) as g1, groupUniqArray(j2.ip_per_flow_per_ttl) as g2
FROM
(SELECT p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, groupUniqArray(p1.reply_ip) as ip_per_flow_per_ttl,
COUNT(DISTINCT(p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, p1.reply_ip)) as u
FROM
(SELECT * from probes_snapshot_2 WHERE dst_ip > 0 AND dst_ip < 1073741824)
AS p1
INNER JOIN
(SELECT * from probes_snapshot_1 WHERE dst_ip > 0 AND dst_ip < 1073741824)
AS p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip)  AND (p1.dst_port = p2.dst_port) AND (p1.ttl = p2.ttl)
GROUP BY (p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port) HAVING u = 1)
AS j1
INNER JOIN
(SELECT p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, groupUniqArray(p1.reply_ip) as ip_per_flow_per_ttl,
COUNT(DISTINCT(p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, p1.reply_ip)) as u
FROM
(SELECT * from probes_pfring_2 WHERE dst_ip > 0 AND dst_ip < 1073741824)
AS p1
INNER JOIN
(SELECT * from probes_pfring_2 WHERE dst_ip > 0 AND dst_ip < 1073741824)
AS p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip)  AND (p1.dst_port = p2.dst_port) AND (p1.ttl = p2.ttl)
GROUP BY (p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port) HAVING u = 1)
AS j2
ON (j1.src_ip = j2.src_ip) AND (j1.dst_ip = j2.dst_ip) AND (j1.dst_port = j2.dst_port) AND (j1.ttl = j2.ttl)
GROUP BY (src_ip, dst_ip, ttl)
HAVING length(arrayIntersect(g1, g2)) = 0
ORDER BY (src_ip, dst_ip, ttl)
)

-- DEBUG

SELECT src_ip, dst_ip, ttl, groupUniqArray(j1.ip_per_flow_per_ttl) as g1, groupUniqArray(j2.ip_per_flow_per_ttl) as g2,
length(arrayIntersect(g1, g2))
FROM
(SELECT p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, groupUniqArray(p1.reply_ip) as ip_per_flow_per_ttl,
COUNT(DISTINCT(p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, p1.reply_ip)) as u
FROM
(SELECT * from probes WHERE dst_ip NOT IN
(SELECT dst_ip FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
-- COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes
WHERE round = 1
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
HAVING cnt > 2 -- OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
AS p1
INNER JOIN
(SELECT * from WHERE dst_ip NOT IN
(SELECT dst_ip FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
-- COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes
WHERE round = 1
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
HAVING cnt > 2 -- OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
)
AS p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip)  AND (p1.dst_port = p2.dst_port) AND (p1.ttl = p2.ttl)
GROUP BY (p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port) HAVING u = 1
)
AS j1
INNER JOIN
(SELECT p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, groupUniqArray(p1.reply_ip)as ip_per_flow_per_ttl,
COUNT(DISTINCT(p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port, p1.reply_ip)) as u
FROM
(SELECT * from probes_pfring_2 WHERE dst_ip = 20994663)
AS p1
INNER JOIN
(SELECT * from probes_pfring_2 WHERE dst_ip = 20994663)
AS p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip)  AND (p1.dst_port = p2.dst_port) AND (p1.ttl = p2.ttl)
GROUP BY (p1.src_ip, p1.dst_ip, p1.ttl, p1.dst_port) HAVING u = 1)
AS j2
ON (j1.src_ip = j2.src_ip) AND (j1.dst_ip = j2.dst_ip) AND (j1.dst_port = j2.dst_port) AND (j1.ttl = j2.ttl)
WHERE ttl = 13
-- WHERE (j1."any(reply_ip)" != j2."any(reply_ip)")
GROUP BY (src_ip, dst_ip, ttl)
ORDER BY (src_ip, dst_ip, ttl)


-- Select all the rows that have changed (Flow, TTL) between 2 snapshots
SELECT DISTINCT(src_ip, dst_ip, dst_port, ttl, p1.reply_ip, p2.reply_ip) FROM
probes_snapshot_2 AS p1
INNER JOIN
probes_snapshot_1 AS p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip)  AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.ttl = p2.ttl)
WHERE
dst_ip not in
(SELECT dst_ip FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes_snapshot_2
WHERE dst_port >= 35000  AND dst_port <= 65000
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
HAVING cnt > 2 OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
GROUP BY (src_ip, dst_ip)
)
AND p1.reply_ip != p2.reply_ip


-- Find the traceroutes that have changed
SELECT DISTINCT(src_ip, dst_ip) FROM
probes_snapshot_2 AS p1
INNER JOIN
probes_snapshot_1 AS p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip)  AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.ttl = p2.ttl)
WHERE
dst_ip not in
(SELECT dst_ip FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes_snapshot_2
WHERE dst_port >= 35000  AND dst_port <= 65000
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
HAVING cnt > 2 OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
GROUP BY (src_ip, dst_ip)
)
AND p1.reply_ip != p2.reply_ip


-- Capture the flow dynamics of nodes at macro level
-- Find the different tracelinks (src_ip, dst_ip, src_port, dst_port, ttl) that identify a link.`
SELECT distinct(p1.reply_ip, p2.reply_ip, p1.dst_ip, p1.ttl, p2.ttl , p1.src_port, p1.dst_port)
FROM (SELECT * FROM probes WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000) as p1
FULL JOIN (SELECT * FROM probes_2 WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000) as p2
ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port=p2.src_port) AND(p1.dst_port = p2.dst_port) AND (p1.ttl = p2.ttl)
WHERE dst_ip not in
(SELECT distinct(dst_ip) FROM
(
SELECT src_ip, dst_ip, ttl,
-- Filter the per packet LB
COUNT(DISTINCT(reply_ip)) as n_ips_per_ttl_flow,
-- Filter the anomalies that answered with more than 1 packet per probe
COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) as cnt
FROM probes
WHERE dst_port >= 33000  AND dst_port <= 65000 AND dst_ip < 100000000
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round)
HAVING cnt > 2 OR n_ips_per_ttl_flow > 1
ORDER BY (src_ip, dst_ip, ttl)
)
)





SELECT
    src_ip,
    dst_ip,
    max(p1.dst_port),
    ttl,
    countDistinct((p1.reply_ip, p2.reply_ip)) AS n_links
FROM
(
    SELECT *
    FROM heartbeat.probes
    WHERE dst_ip > 0 AND dst_ip <= 134217727 AND round <= 1
) AS p1
INNER JOIN
(
    SELECT *
    FROM heartbeat.probes
    WHERE dst_ip > 0 AND dst_ip <= 134217727 AND round <= 1
) AS p2 ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)
WHERE dst_ip NOT IN
(
    SELECT dst_ip
    FROM
    (
        SELECT
            src_ip,
            dst_ip,
            ttl,
            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
            COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt
        FROM heartbeat.probes
        WHERE dst_ip > 0 AND dst_ip <= 134217727
        GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)
        ORDER BY (src_ip, dst_ip, ttl) ASC
    )
    GROUP BY (src_ip, dst_ip)
)
GROUP BY (src_ip, dst_ip, ttl)
HAVING n_links > 1
ORDER BY
    dst_ip ASC,
    ttl ASC





WITH
arraySort(x->x.2,groupUniqArray((reply_ip, snapshot))) as ips_per_snapshot
-- arrayFilter((x-> x.2==1), ips_per_snapshot) as ips_per_snapshot_1,
-- arrayFilter((x-> x.2==2), ips_per_snapshot) as ips_per_snapshot_2
-- arraySort(x->x.3,groupUniqArray((reply_ip, dst_port, snapshot))) as traceroute_ttl_sorted_array,
-- arrayMap((x->x.1), traceroute_ttl_sorted_array) as reply_ips_array,
-- arrayMap((x->x.2), traceroute_ttl_sorted_array) as flow_ids_array
SELECT distinct(src_ip, dst_ip, ttl),
ips_per_snapshot,
-- ips_per_snapshot_1,
-- ips_per_snapshot_2,
-- reply_ips_array,
-- flow_ids_array,


max(dst_port) -- In case we have to remap
FROM
(SELECT *
FROM   versioned_probes
WHERE dst_ip >  200000000  AND dst_ip <=  300000000
)
WHERE dst_ip NOT IN
(
(SELECT dst_ip FROM
(SELECT
        src_ip,
        dst_ip,
        ttl,
        COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
        COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt
    FROM   probes
    WHERE dst_ip >   200000000   AND dst_ip <=   300000000
    GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
    HAVING (cnt > 2) -- OR (n_ips_per_ttl_flow > 1)
    ORDER BY (src_ip, dst_ip, ttl) ASC
)
)
)
GROUP BY (src_ip, dst_ip, ttl)
ORDER BY (src_ip, dst_ip, ttl)
LIMIT 100



SELECT COUNT(DISTINCT (p1.reply_ip, p2.reply_ip))
FROM
(
    SELECT *
    FROM heartbeat.versioned_probes
    WHERE (dst_ip > 0) AND (dst_ip <= 20000000) AND (dst_port >= 33434) AND (dst_port <= 65000) AND (round <= 10)
) AS p1
INNER JOIN
(
    SELECT *
    FROM heartbeat.versioned_probes
    WHERE (dst_ip > 0) AND (dst_ip <= 20000000) AND (dst_port >= 33434) AND (dst_port <= 65000) AND (round <= 10)
) AS p2 ON (p1.src_ip = p2.src_ip) AND (p1.dst_ip = p2.dst_ip) AND (p1.src_port = p2.src_port) AND (p1.dst_port = p2.dst_port) AND (p1.round = p2.round) AND (p1.snapshot = p2.snapshot) AND (toUInt8(p1.ttl + toUInt8(1)) = p2.ttl)
WHERE dst_ip NOT IN
(
    SELECT dst_ip
    FROM
    (
        SELECT
            src_ip,
            dst_ip,
            ttl,
            COUNTDistinct(reply_ip) AS n_ips_per_ttl_flow,
            COUNT((src_ip, dst_ip, ttl, src_port, dst_port)) AS cnt
        FROM heartbeat.versioned_probes
        WHERE (dst_ip > 0) AND (dst_ip <= 20000000) AND (dst_port >= 33434) AND (dst_port <= 65000) AND (round <= 10)
        GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port, round, snapshot)
        HAVING (cnt > 2) OR (n_ips_per_ttl_flow > 1)
        ORDER BY (src_ip, dst_ip, ttl) ASC
    )
    GROUP BY (src_ip, dst_ip)
)
AND p1.reply_ip != p2.reply_ip


select snapshot, count() from
(select src_ip, dst_ip, ttl, src_port, dst_port, any(reply_ip), count(distinct(snapshot)) as hits , any(snapshot) , any(round) , any(type), any(code) from rate_limit_probes
WHERE ttl BETWEEN 3 and 30 AND type=11
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
HAVING hits = 1
ORDER BY (src_ip, dst_ip, ttl, src_port, dst_port)
)
GROUP BY snapshot


select s, count(distinct(src_ip, dst_ip, ttl, src_port, dst_port)) from
(select src_ip, dst_ip, ttl, src_port, dst_port, any(reply_ip), count(distinct(snapshot)) as hits , any(snapshot) as s , any(round) , any(type), any(code)
 from versioned_probes
-- WHERE ttl BETWEEN 3 and 30 AND type=11
WHERE dst_ip between 20000000 AND 30000000 and type = 3 AND dst_ip != reply_ip
GROUP BY (src_ip, dst_ip, ttl, src_port, dst_port)
HAVING hits = 1
-- ORDER BY (src_ip, dst_ip, ttl, src_port, dst_port)
)
GROUP BY s

select sum(c) from
(select snapshot, count(distinct(src_ip, dst_ip, ttl, src_port, dst_port)) as c from
rate_limit_probes
GROUP BY snapshot)


