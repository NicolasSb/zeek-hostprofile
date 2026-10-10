# Settings shared by the cluster tests, standalone and on every node.
redef Site::local_nets += { 10.0.0.0/8 };
redef HostProfile::window_len = 1 min;

@if ( Cluster::is_enabled() )
# Keep the logs in place at shutdown.
redef Log::default_rotation_interval = 0 secs;

@ifdef ( Cluster::Backend::ZeroMQ::listen_xpub_endpoint )
# Free ports from btest instead of the fixed defaults. A node's XPUB
# connects to the central XSUB, and its XSUB to the central XPUB.
const xpub = fmt("tcp://127.0.0.1:%d", port_to_count(to_port(getenv("ZMQ_XPUB_PORT"))));
const xsub = fmt("tcp://127.0.0.1:%d", port_to_count(to_port(getenv("ZMQ_XSUB_PORT"))));
redef Cluster::Backend::ZeroMQ::listen_xpub_endpoint = xpub;
redef Cluster::Backend::ZeroMQ::connect_xsub_endpoint = xpub;
redef Cluster::Backend::ZeroMQ::listen_xsub_endpoint = xsub;
redef Cluster::Backend::ZeroMQ::connect_xpub_endpoint = xsub;
@endif

# The node owning the hosts: the proxy, or the manager when there is none.
function owner(): string
	{
	return Cluster::get_node_count(Cluster::PROXY) > 0 ? "proxy" : "manager";
	}

# The worker reads its trace once its owner is connected, then stops.
event zeek_init()
	{
	if ( Cluster::local_node_type() == Cluster::WORKER )
		suspend_processing();
	}

event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::local_node_type() == Cluster::WORKER && name == owner() )
		continue_processing();
	}

event Pcap::file_done(path: string)
	{
	terminate();
	}

# Each node stops once the node feeding it is gone: worker, proxy, manager.
event Cluster::node_down(name: string, id: string)
	{
	if ( (Cluster::node == owner() && name == "worker") ||
	     (Cluster::node == "manager" && name == "proxy") )
		terminate();
	}
@endif
