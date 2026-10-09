# @TEST-DOC: Smoke test on real traffic: the full log, all columns, without warnings.
# @TEST-EXEC: zeek -r $TRACES/http.pcap $PACKAGE %INPUT >output 2>&1
# @TEST-EXEC: zeek-cut -m -u <hostprofile_features.log >features
# @TEST-EXEC: btest-diff features
# @TEST-EXEC: btest-diff output

redef Site::local_nets += { 10.0.0.0/8 };
