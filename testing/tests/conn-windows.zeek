# @TEST-DOC: Connection features, window rollover, skipped empty window, idle_before, per-host novelty. Scenario: conn_windows() in Scripts/gen-traces.py.
# @TEST-EXEC: zeek -r $TRACES/conn-windows.pcap $PACKAGE %INPUT
# @TEST-EXEC: zeek-cut -m -u ts host idle_before n_conns bytes_out bytes_in n_dst n_dst_ports frac_new_dst frac_internal_dst frac_failed start_cv <hostprofile_features.log >features
# @TEST-EXEC: btest-diff features

redef Site::local_nets += { 10.0.0.0/8 };
redef HostProfile::window_len = 1 min;
