# @TEST-DOC: start_cv(): coefficient of variation of the gaps between connection starts.
# @TEST-EXEC: zeek -b $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

module HostProfile;

event zeek_init()
	{
	print "fewer than 3 starts", start_cv(vector(1.0, 2.0));
	print "regular gaps", start_cv(vector(0.0, 10.0, 20.0, 30.0));
	print "unsorted input", start_cv(vector(30.0, 0.0, 20.0, 10.0));
	print "simultaneous starts", start_cv(vector(5.0, 5.0, 5.0));
	# Gaps 1 and 2: mean 1.5, std 0.5.
	print "irregular gaps", start_cv(vector(0.0, 1.0, 3.0));

	local v = vector(3.0, 1.0, 2.0);
	start_cv(v);
	print "input left unsorted", v;
	}
