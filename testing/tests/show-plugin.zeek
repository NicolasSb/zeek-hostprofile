# @TEST-EXEC: zeek -NN NicolasSb::HostProfile |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
