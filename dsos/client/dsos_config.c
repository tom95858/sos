#include <errno.h>
#include "dsos_priv.h"

int dsos_config_read(const char *config_file)
{
	int		i, ret;
	json_parser_t	parser;
	json_entity_t	j, j_server, j_servers;

	parser = json_parser_new(0);
	ret = json_parse_file(parser, config_file, &g.config);
	if (ret)
		return ret;

	j_servers = json_attr_find(g.config, "servers");
	if (!j_servers) {
		dsos_error("config error: 'servers' attribute not present in %s\n", config_file);
		return -ENOENT;
	}

	g.num_servers = json_list_len(j_servers);
	g.conns = (dsos_conn_t *)calloc(g.num_servers, sizeof(dsos_conn_t));
	if (!g.conns)
		dsos_fatal("out of memory");

	i = 0;
	for (j_server = json_item_first(j_servers); j_server; j_server = json_item_next(j_server)) {
		j = json_attr_find(j_server, "id");
		if (!j)
			dsos_fatal("config error: server #%d missing 'id' attribute\n", i);
		g.conns[i].server_id = json_value_int(j);

		j = json_attr_find(j_server, "host");
		if (!j)
			dsos_fatal("config error: server #%d missing 'host' attribute\n", i);
		g.conns[i].host = json_value_str(j)->str;

		j = json_attr_find(j_server, "service");
		if (!j)
			dsos_fatal("config error: server #%d missing 'service' attribute\n", i);
		g.conns[i].service = json_value_str(j)->str;

		++i;
	}

	j = json_attr_find(g.config, "zap_provider");
	if (j)
		g.opts.zap_prov_name = json_value_str(j)->str;

	j = json_attr_find(g.config, "heap_size");
	if (j)
		g.opts.heap_sz = json_value_int(j);

	j = json_attr_find(g.config, "heap_grain_size");
	if (j)
		g.opts.heap_grain_sz = json_value_int(j);

	json_parser_free(parser);
	return 0;
}
