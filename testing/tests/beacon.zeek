# @TEST-DOC: Per-destination regularity (beacon_cv) next to the overall start_cv. Scenario: beacon() in Scripts/gen-traces.py.
# @TEST-EXEC: zeek -r $TRACES/beacon.pcap $PACKAGE %INPUT
# @TEST-EXEC: zeek-cut -m -u ts host n_conns start_cv beacon_cv <hostprofile_features.log >features
# @TEST-EXEC: btest-diff features

redef Site::local_nets += { 10.0.0.0/8 };
