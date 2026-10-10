# @TEST-DOC: ZeroMQ cluster, with and without proxy: same features as standalone on every trace; without proxy the manager warns.
# @TEST-REQUIRES: zeek -e 'exit(Version::number >= 80100 ? 0 : 1)'
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY_PORT
# @TEST-PORT: BROKER_WORKER_PORT
# @TEST-PORT: ZMQ_XPUB_PORT
# @TEST-PORT: ZMQ_XSUB_PORT
# @TEST-EXEC: cluster-vs-standalone zeromq proxy %INPUT
# @TEST-EXEC: cluster-vs-standalone zeromq noproxy %INPUT
# @TEST-EXEC: grep -oh "HostProfile:.*" noproxy/*/manager/.stderr | sort -u >warning
# @TEST-EXEC: btest-diff warning

@load cluster-control.zeek
