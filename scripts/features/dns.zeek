##! DNS features: query volume, domain diversity and novelty, NXDOMAIN rate.
##!
##! Counts the queries a monitored host sends (names compared in lower case)
##! and matches each reply to its query by connection and DNS id. Only the
##! first reply received within the query's window counts: duplicated, late
##! or unsolicited replies are ignored, so a high NXDOMAIN share means many
##! names that do not exist (typos, misconfiguration, or generated domains).

@load base/protocols/dns
@load ../main

module HostProfile;

export {
	redef record Features += {
		## DNS queries sent by the host.
		n_dns: count &log &default=0;
		## Distinct query names (HyperLogLog estimate).
		n_domains: count &log &default=0;
		## Fraction of queries whose name was never queried before by the
		## host; 0.0 without queries.
		frac_new_domain: double &log &default=0.0;
		## Share of the window's queries answered NXDOMAIN within the same
		## window; 0.0 without queries.
		frac_nxdomain: double &log &default=0.0;
	};

	redef record WindowState += {
		n_dns: count &default=0;
		n_new_domain: count &default=0;
		n_nxdomain: count &default=0;
		domain_hll: opaque of cardinality &optional;
		## Queries of this window still waiting for a reply: [uid, DNS id].
		pending: set[string, count] &default=set();
	};

	redef record HostState += {
		seen_domain: Novelty &optional;
	};
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count, original_query: string)
	{
	local h = c$id$orig_h;
	if ( ! is_monitored(h) )
		return;

	local ws = window_state(h);
	local hs = host_state(h);
	local name = to_lower(query);

	if ( ! ws?$domain_hll )
		ws$domain_hll = new_distinct_counter();
	if ( ! hs?$seen_domain )
		hs$seen_domain = new_novelty();

	ws$n_dns += 1;
	add ws$pending[c$uid, msg$id];
	hll_cardinality_add(ws$domain_hll, name);

	if ( ! seen_before(hs$seen_domain, name) )
		ws$n_new_domain += 1;
	}

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
	{
	# Only the first reply to a query of the open window counts: late,
	# duplicated and unsolicited replies are ignored.
	local h = c$id$orig_h;
	if ( is_orig || h !in windows )
		return;

	local ws = windows[h];
	if ( [c$uid, msg$id] !in ws$pending )
		return;

	delete ws$pending[c$uid, msg$id];
	if ( msg$rcode == 3 )
		ws$n_nxdomain += 1;
	}

hook finalize(h: addr, ws: WindowState, hs: HostState, f: Features)
	{
	if ( ws$n_dns == 0 )
		return;

	local n = ws$n_dns + 0.0;
	f$n_dns = ws$n_dns;
	f$n_domains = double_to_count(floor(hll_cardinality_estimate(ws$domain_hll) + 0.5));
	f$frac_new_domain = ws$n_new_domain / n;
	f$frac_nxdomain = ws$n_nxdomain / n;
	}
