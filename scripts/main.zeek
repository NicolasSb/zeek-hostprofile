##! Per-host behavioral feature extraction over tumbling windows.
##!
##! Activity of each monitored host (a local originator) is accumulated into
##! the currently open window. When the window closes, every feature family
##! fills its columns through the :zeek:see:`HostProfile::finalize` hook and
##! one row per active host is written to ``hostprofile_features.log``.
##!
##! An event is always attributed to the window that is open when Zeek
##! handles it (e.g. a connection belongs to the window in which it is
##! removed). Windows without activity produce no row.
##!
##! Engine only: window clock, per-window/per-host state, HLL and Bloom
##! helpers. Features live in ``features/``, one file per family.

@load base/utils/site

module HostProfile;

export {
	redef enum Log::ID += { FEATURES_LOG };

	global log_policy: Log::PolicyHook;

	## Length of a feature window.
	const window_len = 5 min &redef;

	## Per-host long-lived state (novelty memory) is dropped after this much
	## inactivity.
	const host_expire = 1 day &redef;

	## Relative error of the per-window distinct counters (HyperLogLog).
	## Memory grows as 1/error^2: 0.05 costs about 2 KiB per counter,
	## 0.01 about 64 KiB.
	const distinct_error = 0.05 &redef;

	## A fresh per-window distinct counter.
	global new_distinct_counter: function(): opaque of cardinality;

	## Size and false-positive rate of one generation of novelty memory.
	const novelty_capacity = 10000 &redef;
	const novelty_fp = 0.001 &redef;

	## "Already seen?" memory of one host for one kind of key: two Bloom
	## filter generations. When the current one holds novelty_capacity keys
	## it becomes the previous one and the older is dropped, so the
	## false-positive rate stays near novelty_fp and unused keys age out.
	type Novelty: record {
		cur: opaque of bloomfilter;
		prev: opaque of bloomfilter &optional;
		## Keys added to cur.
		n: count &default=0;
	};

	global new_novelty: function(): Novelty;

	## Returns T if ``key`` is in either generation, and records it in the
	## current one (a key seen again is carried over to the next generation).
	global seen_before: function(nv: Novelty, key: any): bool;

	## One feature vector: a host's activity during one window. Feature
	## families add their columns with ``redef record Features += {...}``.
	type Features: record {
		## Start of the window.
		ts: time &log;
		## The profiled host.
		host: addr &log;
		## Seconds between the end of the host's previous active window and
		## the start of this one; -1.0 for the host's first window.
		idle_before: double &log &default=-1.0;
	};

	## Accumulators for the open window of one host. Families add fields
	## (with ``&default`` or ``&optional``).
	type WindowState: record { };

	## Long-lived state of one host. Families add fields.
	type HostState: record {
		## End of the host's last active window.
		last_active_end: time &optional;
	};

	## Returns T if ``h`` is profiled: a local address per Site::local_nets.
	global is_monitored: function(h: addr): bool;

	## Returns the open-window accumulators of ``h``, creating them if needed.
	global window_state: function(h: addr): WindowState;

	## Returns the long-lived state of ``h``, creating it if needed.
	global host_state: function(h: addr): HostState;

	## Called once per active host when its window closes. Families compute
	## their columns from ``ws``/``hs`` and store them into ``f``.
	global finalize: hook(h: addr, ws: WindowState, hs: HostState, f: Features);

	## Raised for each feature vector, after it has been logged.
	global log_features: event(rec: Features);
}

global windows: table[addr] of WindowState;
global hosts: table[addr] of HostState &read_expire=host_expire;
global window_start: time = double_to_time(0.0);

event zeek_init() &priority=5
	{
	Log::create_stream(FEATURES_LOG, [$columns=Features, $ev=log_features,
	                                  $path="hostprofile_features",
	                                  $policy=log_policy]);
	}

function is_monitored(h: addr): bool
	{
	return Site::is_local_addr(h);
	}

function window_state(h: addr): WindowState
	{
	if ( h !in windows )
		windows[h] = WindowState();
	return windows[h];
	}

function host_state(h: addr): HostState
	{
	if ( h !in hosts )
		hosts[h] = HostState();
	return hosts[h];
	}

function new_distinct_counter(): opaque of cardinality
	{
	return hll_cardinality_init(distinct_error, 0.95);
	}

function new_novelty(): Novelty
	{
	return Novelty($cur=bloomfilter_basic_init(novelty_fp, novelty_capacity));
	}

function seen_before(nv: Novelty, key: any): bool
	{
	if ( bloomfilter_lookup(nv$cur, key) > 0 )
		return T;

	local seen = nv?$prev && bloomfilter_lookup(nv$prev, key) > 0;

	if ( nv$n >= novelty_capacity )
		{
		nv$prev = nv$cur;
		nv$cur = bloomfilter_basic_init(novelty_fp, novelty_capacity);
		nv$n = 0;
		}

	bloomfilter_add(nv$cur, key);
	++nv$n;
	return seen;
	}

function align(t: time): time
	{
	local len = interval_to_double(window_len);
	return double_to_time(floor(time_to_double(t) / len) * len);
	}

function flush_window()
	{
	local wend = window_start + window_len;

	for ( h, ws in windows )
		{
		local hs = host_state(h);
		local f = Features($ts=window_start, $host=h);

		if ( hs?$last_active_end )
			f$idle_before = interval_to_double(window_start - hs$last_active_end);

		hook finalize(h, ws, hs, f);
		Log::write(FEATURES_LOG, f);
		hs$last_active_end = wend;
		}

	windows = table();
	}

event HostProfile::close_window()
	{
	# At shutdown Zeek expires pending timers: the last window is flushed by
	# zeek_done instead, after all connections have been removed.
	if ( zeek_is_terminating() )
		return;

	flush_window();
	window_start = window_start + window_len;

	# Skip windows that passed without any packet: they have no activity.
	if ( window_start + window_len <= network_time() )
		window_start = align(network_time());

	schedule (window_start + window_len - network_time()) { HostProfile::close_window() };
	}

event network_time_init()
	{
	window_start = align(network_time());
	schedule (window_start + window_len - network_time()) { HostProfile::close_window() };
	}

event zeek_done()
	{
	# Last, possibly partial, window.
	flush_window();
	}
