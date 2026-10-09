##! TLS features: SNI volume and novelty.
##!
##! The SNI is the server name a TLS client announces in clear text in its
##! hello. Counts the hellos of a monitored host that carry one (first name,
##! lower case) and the share of names never seen before for that host.

@load base/protocols/ssl
@load ../main

module HostProfile;

export {
	redef record Features += {
		## TLS client hellos carrying an SNI.
		n_sni: count &log &default=0;
		## Fraction of SNIs never seen before for the host; 0.0 without SNI.
		frac_new_sni: double &log &default=0.0;
	};

	redef record WindowState += {
		n_sni: count &default=0;
		n_new_sni: count &default=0;
	};

	redef record HostState += {
		seen_sni: Novelty &optional;
	};
}

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
	{
	local h = c$id$orig_h;
	if ( ! is_client || |names| == 0 || ! is_monitored(h) )
		return;

	local ws = window_state(h);
	local hs = host_state(h);
	local sni = to_lower(names[0]);

	if ( ! hs?$seen_sni )
		hs$seen_sni = new_novelty();

	ws$n_sni += 1;
	if ( ! seen_before(hs$seen_sni, sni) )
		ws$n_new_sni += 1;
	}

hook finalize(h: addr, ws: WindowState, hs: HostState, f: Features)
	{
	if ( ws$n_sni == 0 )
		return;

	f$n_sni = ws$n_sni;
	f$frac_new_sni = ws$n_new_sni / (ws$n_sni + 0.0);
	}
