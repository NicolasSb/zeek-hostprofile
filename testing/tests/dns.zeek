# @TEST-DOC: DNS features: case-insensitive names, NXDOMAIN, duplicate and missing replies. Scenario: dns() in Scripts/gen-traces.py.
# @TEST-EXEC: zeek -r $TRACES/dns.pcap $PACKAGE %INPUT
# @TEST-EXEC: zeek-cut -m -u ts host n_dns n_domains frac_new_domain frac_nxdomain <hostprofile_features.log >features
# @TEST-EXEC: btest-diff features

redef Site::local_nets += { 10.0.0.0/8 };
