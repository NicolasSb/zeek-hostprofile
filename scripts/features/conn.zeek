##! Connection-level features: volume, diversity, novelty, structure, rhythm.
##!
##! Counts every connection originated by a monitored host when Zeek removes
##! it, in the window of its last packet (so a long connection is counted,
##! with all its bytes, in the window where it ends). Columns: connection
##! count, payload bytes out/in, distinct destinations and ports, share of
##! never-seen destinations, share of local destinations, share of failed
##! attempts, and the regularity of connection starts (near 0 = clockwork
##! rhythm, e.g. beaconing): overall (``start_cv``) and towards the most
##! regular destination in the window (``beacon_cv``). Beacons slower than
##! about one per minute, or sent in bursts, are not caught.

@load base/protocols/conn
@load ../main

module HostProfile;

export {
	## Connection states counted as failed attempts.
	const failed_states: set[string] = { "S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR" } &redef;

	## Connections to one destination within a window needed to measure
	## its regularity (beacon_cv).
	const beacon_min_conns = 4 &redef;

	redef record Features += {
		## Connections removed during the window.
		n_conns: count &log &default=0;
		## Sum of originator / responder payload bytes.
		bytes_out: count &log &default=0;
		bytes_in: count &log &default=0;
		## Distinct responder addresses and ports (HyperLogLog estimate).
		n_dst: count &log &default=0;
		n_dst_ports: count &log &default=0;
		## Fraction of connections whose responder was never seen before
		## for this host.
		frac_new_dst: double &log &default=0.0;
		## Fraction of connections to a local responder.
		frac_internal_dst: double &log &default=0.0;
		## Fraction of connections in a failed state (see failed_states).
		frac_failed: double &log &default=0.0;
		## Coefficient of variation (population std / mean) of the gaps
		## between sorted connection start times; -1.0 if fewer than 3
		## connections or a zero mean gap.
		start_cv: double &log &default=-1.0;
		## Lowest start_cv among the destinations contacted at least
		## beacon_min_conns times; -1.0 if none.
		beacon_cv: double &log &default=-1.0;
	};

	redef record WindowState += {
		n_conns: count &default=0;
		bytes_out: count &default=0;
		bytes_in: count &default=0;
		n_new_dst: count &default=0;
		n_internal: count &default=0;
		n_failed: count &default=0;
		dst_hll: opaque of cardinality &optional;
		port_hll: opaque of cardinality &optional;
		## Connection start times, per destination.
		dst_starts: table[addr] of vector of double &default=table();
	};

	redef record HostState += {
		seen_dst: Novelty &optional;
	};

	## A removed connection, as sent by the worker.
	type ConnObs: record {
		dst: addr;
		dst_port: port;
		orig_bytes: count;
		resp_bytes: count;
		state: string;
		start: time;
	};

	redef record Observation += {
		conn: ConnObs &optional;
	};
}

event connection_state_remove(c: connection) &priority=-5
	{
	local h = c$id$orig_h;
	if ( ! is_monitored(h) || ! c?$conn )
		return;

	# Stamped with its last packet: the removal itself may come much later.
	send(Observation($host=h, $ts=c$start_time + c$duration, $conn=ConnObs(
	    $dst=c$id$resp_h, $dst_port=c$id$resp_p,
	    $orig_bytes=c$conn?$orig_bytes ? c$conn$orig_bytes : 0,
	    $resp_bytes=c$conn?$resp_bytes ? c$conn$resp_bytes : 0,
	    $state=c$conn$conn_state, $start=c$start_time)));
	}

hook observe(o: Observation)
	{
	if ( ! o?$conn )
		return;

	local co = o$conn;
	local ws = window_state(o$host);
	local hs = host_state(o$host);
	local dst = co$dst;

	if ( ! ws?$dst_hll )
		{
		ws$dst_hll = new_distinct_counter();
		ws$port_hll = new_distinct_counter();
		}
	if ( ! hs?$seen_dst )
		hs$seen_dst = new_novelty();

	ws$n_conns += 1;
	ws$bytes_out += co$orig_bytes;
	ws$bytes_in += co$resp_bytes;
	hll_cardinality_add(ws$dst_hll, dst);
	hll_cardinality_add(ws$port_hll, co$dst_port);

	if ( ! seen_before(hs$seen_dst, dst) )
		ws$n_new_dst += 1;

	if ( Site::is_local_addr(dst) )
		ws$n_internal += 1;

	if ( co$state in failed_states )
		ws$n_failed += 1;

	if ( dst !in ws$dst_starts )
		ws$dst_starts[dst] = vector();
	ws$dst_starts[dst] += time_to_double(co$start);
	}

function start_cv(starts: vector of double): double
	{
	if ( |starts| < 3 )
		return -1.0;

	local s = copy(starts);
	sort(s);
	local n = |s| - 1;
	local sum = 0.0;
	local i = 0;
	while ( i < n )
		{
		sum += s[i + 1] - s[i];
		++i;
		}
	local mean = sum / n;
	if ( mean == 0.0 )
		return -1.0;

	local sq = 0.0;
	i = 0;
	while ( i < n )
		{
		local d = (s[i + 1] - s[i]) - mean;
		sq += d * d;
		++i;
		}
	return sqrt(sq / n) / mean;
	}

hook finalize(h: addr, ws: WindowState, hs: HostState, f: Features)
	{
	if ( ws$n_conns == 0 )
		return;

	local n = ws$n_conns + 0.0;
	f$n_conns = ws$n_conns;
	f$bytes_out = ws$bytes_out;
	f$bytes_in = ws$bytes_in;
	f$n_dst = double_to_count(floor(hll_cardinality_estimate(ws$dst_hll) + 0.5));
	f$n_dst_ports = double_to_count(floor(hll_cardinality_estimate(ws$port_hll) + 0.5));
	f$frac_new_dst = ws$n_new_dst / n;
	f$frac_internal_dst = ws$n_internal / n;
	f$frac_failed = ws$n_failed / n;
	local starts: vector of double = vector();
	for ( _, s in ws$dst_starts )
		{
		for ( i in s )
			starts += s[i];

		if ( |s| < beacon_min_conns )
			next;

		local cv = start_cv(s);
		if ( cv >= 0.0 && (f$beacon_cv < 0.0 || cv < f$beacon_cv) )
			f$beacon_cv = cv;
		}
	f$start_cv = start_cv(starts);
	}
