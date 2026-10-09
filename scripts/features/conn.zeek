##! Connection-level features: volume, diversity, novelty, structure, rhythm.
##!
##! Counts every connection originated by a monitored host when Zeek removes
##! it (so a long connection is counted, with all its bytes, in the window
##! where it ends). Columns: connection count, payload bytes out/in, distinct
##! destinations and ports, share of never-seen destinations, share of local
##! destinations, share of failed attempts, and ``start_cv``, the regularity
##! of connection starts (near 0 = clockwork rhythm, e.g. beaconing).

@load base/protocols/conn
@load ../main

module HostProfile;

export {
	## Connection states counted as failed attempts.
	const failed_states: set[string] = { "S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR" } &redef;

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
		starts: vector of double &default=vector();
	};

	redef record HostState += {
		seen_dst: Novelty &optional;
	};
}

event connection_state_remove(c: connection) &priority=-5
	{
	local h = c$id$orig_h;
	if ( ! is_monitored(h) || ! c?$conn )
		return;

	local ws = window_state(h);
	local hs = host_state(h);
	local dst = c$id$resp_h;

	if ( ! ws?$dst_hll )
		{
		ws$dst_hll = new_distinct_counter();
		ws$port_hll = new_distinct_counter();
		}
	if ( ! hs?$seen_dst )
		hs$seen_dst = new_novelty();

	ws$n_conns += 1;
	ws$bytes_out += c$conn?$orig_bytes ? c$conn$orig_bytes : 0;
	ws$bytes_in += c$conn?$resp_bytes ? c$conn$resp_bytes : 0;
	hll_cardinality_add(ws$dst_hll, dst);
	hll_cardinality_add(ws$port_hll, c$id$resp_p);

	if ( ! seen_before(hs$seen_dst, dst) )
		ws$n_new_dst += 1;

	if ( Site::is_local_addr(dst) )
		ws$n_internal += 1;

	if ( c$conn$conn_state in failed_states )
		ws$n_failed += 1;

	ws$starts += time_to_double(c$start_time);
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
	f$start_cv = start_cv(ws$starts);
	}
