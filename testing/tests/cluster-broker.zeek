# @TEST-DOC: Broker cluster, with and without proxy: same features as standalone on every trace; without proxy the manager warns.
# @TEST-PORT: BROKER_MANAGER_PORT
# @TEST-PORT: BROKER_PROXY_PORT
# @TEST-PORT: BROKER_WORKER_PORT
# @TEST-PORT: ZMQ_XPUB_PORT
# @TEST-PORT: ZMQ_XSUB_PORT
# @TEST-EXEC: cluster-vs-standalone broker proxy %INPUT
# @TEST-EXEC: cluster-vs-standalone broker noproxy %INPUT
# @TEST-EXEC: grep -oh "HostProfile:.*" noproxy/*/manager/.stderr | sort -u >warning
# @TEST-EXEC: btest-diff warning

@load cluster-control.zeek
