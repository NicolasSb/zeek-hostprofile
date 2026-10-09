# @TEST-DOC: TLS features: SNI count and case-insensitive novelty. Scenario: tls() in Scripts/gen-traces.py.
# @TEST-EXEC: zeek -r $TRACES/tls.pcap $PACKAGE %INPUT
# @TEST-EXEC: zeek-cut -m -u ts host n_sni frac_new_sni <hostprofile_features.log >features
# @TEST-EXEC: btest-diff features

redef Site::local_nets += { 10.0.0.0/8 };
