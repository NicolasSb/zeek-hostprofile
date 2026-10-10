##! Per-host behavioral feature extraction over tumbling windows.
##!
##! Activity of each monitored host (a local originator) is accumulated into
##! the currently open window. When the window closes, every feature family
##! fills its columns through the :zeek:see:`HostProfile::finalize` hook and
##! one row per active host is written to ``hostprofile_features.log``.
##!
##! An event is attributed to the window containing its timestamp (for a
##! connection, its last packet). An event whose window is already closed
##! counts in the next one. Windows without activity produce no row.
##!
##! In a cluster, workers only observe: each event becomes an Observation
##! sent to the host's owner (a proxy chosen by hashing the host, else the
##! manager), which keeps the windows and writes the rows. Standalone, the
##! process is its own owner. Windows follow the observations' timestamps.
##!
##! Engine only: window clock, per-window/per-host state, HLL and Bloom
##! helpers. Features live in ``features/``, one file per family.

@load base/frameworks/cluster
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

	## Extra wait, on the owner's clock, before closing a window: covers the
	## delay of observations sent by workers.
	const close_delay = 5 sec &redef;

	## One observed event of a monitored host. Families add an ``&optional``
	## field holding their own data.
	type Observation: record {
		host: addr;
		## When the event happened (packet time).
		ts: time;
	};

	## Sends ``o`` to the owner of its host (see module doc).
	global send: function(o: Observation);

	## Run by the owner for each observation. The engine first moves the
	## window clock; families then fill WindowState/HostState.
	global observe: hook(o: Observation);

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
global window_open = F;
global window_start: time = double_to_time(0.0);
## End of the last flushed window: later observations never reopen it.
global closed_until: time = double_to_time(0.0);
## Latest observation timestamp: the owner's view of the packets' clock.
global latest: time = double_to_time(0.0);

global observe_remote: event(o: Observation);
global close_window: event(start: time);

event zeek_init() &priority=5
	{
	Log::create_stream(FEATURES_LOG, [$columns=Features, $ev=log_features,
	                                  $path="hostprofile_features",
	                                  $policy=log_policy]);

	if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER &&
	     Cluster::get_node_count(Cluster::PROXY) == 0 )
		Reporter::warning("HostProfile: no proxy in the cluster, the manager computes all features");
	}

function send(o: Observation)
	{
	if ( ! Cluster::is_enabled() )
		{
		hook observe(o);
		return;
		}

	if ( ! Cluster::publish_hrw(Cluster::proxy_pool, o$host, observe_remote, o) )
		Cluster::publish(Cluster::manager_topic, observe_remote, o);
	}

event observe_remote(o: Observation)
	{
	hook observe(o);
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
	if ( ! window_open )
		return;

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
	window_open = F;
	closed_until = wend;
	}

# Makes the window holding ``ts`` the open one. A late ``ts`` counts in the
# open window, or in the next one if its window is already closed.
function advance(ts: time)
	{
	if ( ts > latest )
		latest = ts;

	if ( window_open && ts < window_start + window_len )
		return;

	flush_window();

	window_start = align(ts);
	if ( window_start < closed_until )
		window_start = closed_until;
	window_open = T;

	# Relative to the packets' clock, so a proxy (which sees no packets)
	# waits the right time too.
	local wait = window_start + window_len - latest;
	if ( wait < 0 sec )
		wait = 0 sec;
	schedule (wait + close_delay) { HostProfile::close_window(window_start) };
	}

hook observe(o: Observation) &priority=100
	{
	advance(o$ts);
	}

event HostProfile::close_window(start: time)
	{
	# At shutdown Zeek expires pending timers: the last window is flushed by
	# zeek_done instead, after all connections have been removed.
	if ( zeek_is_terminating() || ! window_open || start != window_start )
		return;

	flush_window();
	}

event zeek_done()
	{
	# Last, possibly partial, window.
	flush_window();
	}
