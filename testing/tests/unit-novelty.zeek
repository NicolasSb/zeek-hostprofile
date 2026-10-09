# @TEST-DOC: seen_before(): novelty memory with two rotating Bloom filter generations.
# @TEST-EXEC: zeek -b $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

module HostProfile;

# Tiny generations so that rotation happens after two keys.
redef novelty_capacity = 2;

event zeek_init()
	{
	local nv = new_novelty();
	print "a", seen_before(nv, "a");  # new
	print "a", seen_before(nv, "a");  # seen
	print "b", seen_before(nv, "b");  # new; cur = {a, b} is now full
	print "c", seen_before(nv, "c");  # new; rotation: prev = {a, b}, cur = {c}
	print "a", seen_before(nv, "a");  # seen in prev, carried over: cur = {c, a}
	print "d", seen_before(nv, "d");  # new; rotation: prev = {c, a}, cur = {d}
	print "b", seen_before(nv, "b");  # aged out: new again
	print "a", seen_before(nv, "a");  # still remembered
	}
