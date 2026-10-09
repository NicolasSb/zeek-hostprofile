#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::NicolasSb_HostProfile { Plugin plugin; }

using namespace zeek::plugin::NicolasSb_HostProfile;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "NicolasSb::HostProfile";
	config.description = "TODO: Insert description";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
