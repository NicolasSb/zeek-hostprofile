# @TEST-DOC: align(): window start containing a given time.
# @TEST-EXEC: zeek -b $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

module HostProfile;

redef window_len = 1 min;

event zeek_init()
	{
	print "on a boundary", time_to_double(align(double_to_time(1700000100.0)));
	print "inside", time_to_double(align(double_to_time(1700000135.5)));
	print "just before the next", time_to_double(align(double_to_time(1700000159.999)));
	}
