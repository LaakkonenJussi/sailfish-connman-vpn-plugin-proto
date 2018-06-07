/*
 *
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2010-2014  BMW Car IT GmbH.
 *  Copyright (C) 2016-2018 Jolla Ltd.
 *
 *  Contact: jussi.laakkonen@jolla.com
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define CONNMAN_API_SUBJECT_TO_CHANGE

#define PLUGIN_NAME "protovpn"
#define BIN_PATH "/usr/sbin/openvpn"	// Path to VPN binary
#define SCRIPTDIR "/usr/lib/connman/scripts"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>
#include <dbus/dbus.h>

#include <linux/if_tun.h> 		// For IFF_TUN/IFF_TAP
 
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#include <connman/plugin.h> 		// Connman plugin registration
#include <connman/task.h> 		// Connman binary execution
#include <connman/log.h>		// Connman logging functions

#include <connman/dbus.h>
#include <connman/ipconfig.h>
#include <connman/agent.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include <connman/vpn/plugins/vpn.h>	// VPN main header
#include <connman/vpn/vpn-agent.h> 	// VPN agent header


static DBusConnection *connection;

struct {
	const char *cm_opt;
	const char *ov_opt;
	char       has_value;
} ov_options[] = {
	{ "Host", "--remote", 1 },
	{ "ProtoVPN.CACert", "--ca", 1 },
	{ "ProtoVPN.Cert", "--cert", 1 },
	{ "ProtoVPN.Key", "--key", 1 },
	{ "ProtoVPN.MTU", "--tun-mtu", 1 },
	{ "ProtoVPN.NSCertType", "--ns-cert-type", 1 },
	{ "ProtoVPN.Proto", "--proto", 1 },
	{ "ProtoVPN.Port", "--port", 1 },
	{ "ProtoVPN.AuthUserPass", "--auth-user-pass", 1 },
	{ "ProtoVPN.AskPass", "--askpass", 1 },
	{ "ProtoVPN.AuthNoCache", "--auth-nocache", 0 },
	{ "ProtoVPN.TLSRemote", "--tls-remote", 1 },
	{ "ProtoVPN.TLSAuth", NULL, 1 },
	{ "ProtoVPN.TLSAuthDir", NULL, 1 },
	{ "ProtoVPN.Cipher", "--cipher", 1 },
	{ "ProtoVPN.Auth", "--auth", 1 },
	{ "ProtoVPN.CompLZO", "--comp-lzo", 0 },
	{ "ProtoVPN.RemoteCertTls", "--remote-cert-tls", 1 },
	{ "ProtoVPN.ConfigFile", "--config", 1 },
	{ "ProtoVPN.DeviceType", NULL, 1 },
	{ "ProtoVPN.Verb", "--verb", 1 },
};

struct ov_private_data {
	struct vpn_provider *provider;
	struct connman_task *task;
	char *dbus_sender;
	char *if_name;
	vpn_provider_connect_cb_t cb;
	void *user_data;
	char *mgmt_path;
	guint mgmt_timer_id;
	int mgmt_socket_fd;
	guint mgmt_event_id;
	GIOChannel *mgmt_channel;
	int connect_attempts;
	int failed_attempts;
};

static void free_private_data(struct ov_private_data *data)
{
	g_free(data->dbus_sender);
	g_free(data->if_name);
	g_free(data->mgmt_path);
	g_free(data);
}

struct nameserver_entry {
	int id;
	char *nameserver;
};

static struct nameserver_entry *ov_append_dns_entries(const char *key,
						const char *value)
{
	struct nameserver_entry *entry = NULL;
	gchar **options;

	if (!g_str_has_prefix(key, "foreign_option_"))
		return NULL;

	options = g_strsplit(value, " ", 3);
	if (options[0] &&
		!strcmp(options[0], "dhcp-option") &&
			options[1] &&
			!strcmp(options[1], "DNS") &&
				options[2]) {

		entry = g_try_new(struct nameserver_entry, 1);
		if (!entry)
			return NULL;

		entry->nameserver = g_strdup(options[2]);
		entry->id = atoi(key + 15); /* foreign_option_XXX */
	}

	g_strfreev(options);

	return entry;
}

static char *ov_get_domain_name(const char *key, const char *value)
{
	gchar **options;
	char *domain = NULL;

	if (!g_str_has_prefix(key, "foreign_option_"))
		return NULL;

	options = g_strsplit(value, " ", 3);
	if (options[0] &&
		!strcmp(options[0], "dhcp-option") &&
			options[1] &&
			!strcmp(options[1], "DOMAIN") &&
				options[2]) {

		domain = g_strdup(options[2]);
	}

	g_strfreev(options);

	return domain;
}

static gint cmp_ns(gconstpointer a, gconstpointer b)
{
	struct nameserver_entry *entry_a = (struct nameserver_entry *)a;
	struct nameserver_entry *entry_b = (struct nameserver_entry *)b;

	if (entry_a->id < entry_b->id)
		return -1;

	if (entry_a->id > entry_b->id)
		return 1;

	return 0;
}

static void free_ns_entry(gpointer data)
{
	struct nameserver_entry *entry = data;

	g_free(entry->nameserver);
	g_free(entry);
}

static int ov_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	char *address = NULL, *gateway = NULL, *peer = NULL, *netmask = NULL;
	struct connman_ipaddress *ipaddress;
	GSList *nameserver_list = NULL;

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "up"))
		return VPN_STATE_DISCONNECT;


	vpn_provider_set_string(provider, "DefaultRoute", "false");

	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		struct nameserver_entry *ns_entry = NULL;
		DBusMessageIter entry;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("%s = %s", key, value);

		if (!strcmp(key, "trusted_ip"))
			gateway = g_strdup(value);

		if (!strcmp(key, "ifconfig_local"))
			address = g_strdup(value);

		if (!strcmp(key, "ifconfig_netmask"))
			netmask = g_strdup(value);

		if (!strcmp(key, "ifconfig_remote"))
			peer = g_strdup(value);

		if (g_str_has_prefix(key, "route_"))
			vpn_provider_append_route(provider, key, value);

		if ((ns_entry = ov_append_dns_entries(key, value)))
			nameserver_list = g_slist_prepend(nameserver_list,
							ns_entry);
		else {
			char *domain = ov_get_domain_name(key, value);
			if (domain) {
				vpn_provider_set_domain(provider, domain);
				g_free(domain);
			}
		}

		dbus_message_iter_next(&dict);
	}

	ipaddress = connman_ipaddress_alloc(AF_INET);
	if (!ipaddress) {
		g_slist_free_full(nameserver_list, free_ns_entry);
		g_free(address);
		g_free(gateway);
		g_free(peer);
		g_free(netmask);

		return VPN_STATE_FAILURE;
	}

	connman_ipaddress_set_ipv4(ipaddress, address, netmask, gateway);
	connman_ipaddress_set_peer(ipaddress, peer);
	vpn_provider_set_ipaddress(provider, ipaddress);

	if (nameserver_list) {
		char *nameservers = NULL;
		GSList *tmp;

		nameserver_list = g_slist_sort(nameserver_list, cmp_ns);
		for (tmp = nameserver_list; tmp;
						tmp = g_slist_next(tmp)) {
			struct nameserver_entry *ns = tmp->data;

			if (!nameservers) {
				nameservers = g_strdup(ns->nameserver);
			} else {
				char *str;
				str = g_strjoin(" ", nameservers,
						ns->nameserver, NULL);
				g_free(nameservers);
				nameservers = str;
			}
		}

		g_slist_free_full(nameserver_list, free_ns_entry);

		vpn_provider_set_nameservers(provider, nameservers);

		g_free(nameservers);
	}

	g_free(address);
	g_free(gateway);
	g_free(peer);
	g_free(netmask);
	connman_ipaddress_free(ipaddress);

	return VPN_STATE_CONNECT;
}

static int ov_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ov_options); i++) {
		if (strncmp(ov_options[i].cm_opt, "ProtoVPN.", 8) == 0) {
			option = vpn_provider_get_string(provider,
							ov_options[i].cm_opt);
			if (!option)
				continue;

			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					ov_options[i].cm_opt, option);
		}
	}
	return 0;
}

static int task_append_config_data(struct vpn_provider *provider,
					struct connman_task *task)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ov_options); i++) {
		if (!ov_options[i].ov_opt)
			continue;

		option = vpn_provider_get_string(provider,
					ov_options[i].cm_opt);
		if (!option)
			continue;

		/*
		 * If the AuthUserPass option is "-", provide the input
		 * via management interface
		 */
		if (!strcmp(ov_options[i].cm_opt, "ProtoVPN.AuthUserPass") &&
						!strcmp(option, "-")) {
			option = NULL;
		}

		if (connman_task_add_argument(task,
				ov_options[i].ov_opt,
				ov_options[i].has_value ? option : NULL) < 0) {
			return -EIO;
		}
	}

	return 0;
}

static void close_management_interface(struct ov_private_data *data)
{
	if (data->mgmt_path) {
		if (unlink(data->mgmt_path) != 0 && errno != ENOENT) {
			connman_warn("Unable to unlink management socket %s: %d",
						data->mgmt_path, errno);
		}
		g_free(data->mgmt_path);
		data->mgmt_path = NULL;
	}
	if (data->mgmt_timer_id != 0) {
		g_source_remove(data->mgmt_timer_id);
		data->mgmt_timer_id = 0;
	}
	if (data->mgmt_socket_fd != -1) {
		close(data->mgmt_socket_fd);
		data->mgmt_socket_fd = -1;
	}
	if (data->mgmt_event_id) {
		g_source_remove(data->mgmt_event_id);
		data->mgmt_event_id = 0;
	}
	if (data->mgmt_channel) {
		g_io_channel_shutdown(data->mgmt_channel, FALSE, NULL);
		g_io_channel_unref(data->mgmt_channel);
		data->mgmt_channel = NULL;
	}
}

static void ov_died(struct connman_task *task, int exit_code, void *user_data)
{
	struct ov_private_data *data = user_data;

	/* Cancel any pending agent requests */
	connman_agent_cancel(data);

	close_management_interface(data);

	vpn_died(task, exit_code, data->provider);

	free_private_data(data);
}

static int run_connect(struct ov_private_data *data,
			vpn_provider_connect_cb_t cb, void *user_data)
{
	struct vpn_provider *provider = data->provider;
	struct connman_task *task = data->task;
	const char *option;
	int fd;
	int err = 0;

	option = vpn_provider_get_string(provider, "ProtoVPN.ConfigFile");
	if (!option) {
		/*
		 * Set some default options if user has no config file.
		 */
		option = vpn_provider_get_string(provider, "ProtoVPN.TLSAuth");
		if (option) {
			connman_task_add_argument(task, "--tls-auth", option);
			option = vpn_provider_get_string(provider,
							"ProtoVPN.TLSAuthDir");
			if (option)
				connman_task_add_argument(task, option, NULL);
		}

		connman_task_add_argument(task, "--nobind", NULL);
		connman_task_add_argument(task, "--persist-key", NULL);
		connman_task_add_argument(task, "--client", NULL);
	}

	if (data->mgmt_path) {
		connman_task_add_argument(task, "--management", NULL);
		connman_task_add_argument(task, data->mgmt_path, NULL);
		connman_task_add_argument(task, "unix", NULL);
		connman_task_add_argument(task, "--management-query-passwords",
								NULL);
		connman_task_add_argument(task, "--auth-retry", "interact");
	}

	connman_task_add_argument(task, "--syslog", NULL);

	connman_task_add_argument(task, "--script-security", "2");

	connman_task_add_argument(task, "--up",
					SCRIPTDIR "/openvpn-script");
	connman_task_add_argument(task, "--up-restart", NULL);

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_BUSNAME",
					dbus_bus_get_unique_name(connection));

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_INTERFACE",
					CONNMAN_TASK_INTERFACE);

	connman_task_add_argument(task, "--setenv", NULL);
	connman_task_add_argument(task, "CONNMAN_PATH",
					connman_task_get_path(task));

	connman_task_add_argument(task, "--dev", data->if_name);
	option = vpn_provider_get_string(provider, "ProtoVPN.DeviceType");
	if (option) {
		connman_task_add_argument(task, "--dev-type", option);
	} else {
		/*
		 * Default to tun for backwards compatibility.
		 */
		connman_task_add_argument(task, "--dev-type", "tun");
	}

	connman_task_add_argument(task, "--persist-tun", NULL);

	connman_task_add_argument(task, "--route-noexec", NULL);
	connman_task_add_argument(task, "--ifconfig-noexec", NULL);

	/*
	 * Disable client restarts because we can't handle this at the
	 * moment. The problem is that when ProtoVPN decides to switch
	 * from CONNECTED state to RECONNECTING and then to RESOLVE,
	 * it is not possible to do a DNS lookup. The DNS server is
	 * not accessable through the tunnel anymore and so we end up
	 * trying to resolve the ProtoVPN servers address.
	 */
	connman_task_add_argument(task, "--ping-restart", "0");

	fd = fileno(stderr);
	err = connman_task_run(task, ov_died, data,
			NULL, &fd, &fd);
	if (err < 0) {
		connman_error("protovpn failed to start");
		err = -EIO;
		goto done;
	}

done:
	if (cb)
		cb(provider, user_data, err);

	return err;
}

static char *ov_quote_credential(char *pos, const char *cred)
{
	*pos++ = '\"';
	while (*cred != '\0') {
		if (*cred == ' ' || *cred == '"' || *cred == '\\') {
			*pos++ = '\\';
		}
		*pos++ = *cred++;
	}
	*pos++ = '\"';
	return pos;
}

static void ov_return_credentials(struct ov_private_data *data,
				const char *username, const char *password)
{
	char *fmt[2] = { "username \"Auth\" ", "password \"Auth\" " };
	char *reply, *pos;

	pos = reply = g_malloc0((strlen(username) + strlen(password)) * 2
				+ strlen(fmt[0]) + strlen(fmt[1]) + 7);
	pos += sprintf(pos, fmt[0], NULL);
	pos = ov_quote_credential(pos, username);
	pos += sprintf(pos, "\n");
	pos += sprintf(pos, fmt[1], NULL);
	pos = ov_quote_credential(pos, password);
	pos += sprintf(pos, "\n");

	g_io_channel_write_chars(data->mgmt_channel, reply, strlen(reply),
								NULL, NULL);
	g_io_channel_flush(data->mgmt_channel, NULL);

	memset(reply, 0, strlen(reply));
	g_free(reply);
}

static void request_input_append_informational(DBusMessageIter *iter,
		void *user_data)
{
	char *str = "string";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "informational";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_append_mandatory(DBusMessageIter *iter,
		void *user_data)
{
	char *str = "string";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_append_password(DBusMessageIter *iter,
		void *user_data)
{
	char *str = "password";

	connman_dbus_dict_append_basic(iter, "Type",
				DBUS_TYPE_STRING, &str);
	str = "mandatory";
	connman_dbus_dict_append_basic(iter, "Requirement",
				DBUS_TYPE_STRING, &str);
}

static void request_input_credentials_reply(DBusMessage *reply, void *user_data)
{
	struct ov_private_data *data = user_data;
	char *password = NULL, *username = NULL;
	char *key;
	DBusMessageIter iter, dict;

	DBG("provider %p", data->provider);

	if (!reply || dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto err;

	if (!vpn_agent_check_reply_has_dict(reply))
		goto err;

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "ProtoVPN.Password")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &password);
			vpn_provider_set_string_hide_value(data->provider,
					key, password);

		} else if (g_str_equal(key, "ProtoVPN.Username")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &username);
			vpn_provider_set_string_hide_value(data->provider,
					key, username);
		}

		dbus_message_iter_next(&dict);
	}

	if (!password || !username)
		goto err;

	ov_return_credentials(data, username, password);

	return;

err:
	vpn_provider_indicate_error(data->provider,
			VPN_PROVIDER_ERROR_AUTH_FAILED);
}

static int request_credentials_input(struct ov_private_data *data)
{
	DBusMessage *message;
	const char *path, *agent_sender, *agent_path;
	DBusMessageIter iter;
	DBusMessageIter dict;
	int err;
	void *agent;

	agent = connman_agent_get_info(data->dbus_sender, &agent_sender,
							&agent_path);
	if (!data->provider || !agent || !agent_path)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					VPN_AGENT_INTERFACE,
					"RequestInput");
	if (!message)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = vpn_provider_get_path(data->provider);
	dbus_message_iter_append_basic(&iter,
				DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);

	if (data->failed_attempts > 0) {
		connman_dbus_dict_append_dict(&dict, "VpnAgent.AuthFailure",
			request_input_append_informational, NULL);
	}

	/* Request temporary properties to pass on to protovpn */
	connman_dbus_dict_append_dict(&dict, "ProtoVPN.Username",
			request_input_append_mandatory, NULL);

	connman_dbus_dict_append_dict(&dict, "ProtoVPN.Password",
			request_input_append_password, NULL);

	vpn_agent_append_host_and_name(&dict, data->provider);

	connman_dbus_dict_close(&iter, &dict);

	err = connman_agent_queue_message(data, message,
			connman_timeout_input_request(),
			request_input_credentials_reply, data, agent);

	if (err < 0 && err != -EBUSY) {
		DBG("error %d sending agent request", err);
		dbus_message_unref(message);

		return err;
	}

	dbus_message_unref(message);

	return -EINPROGRESS;
}


static gboolean ov_management_handle_input(GIOChannel *source,
				GIOCondition condition, gpointer user_data)
{
	struct ov_private_data *data = user_data;
	char *str = NULL;
	int err = 0;
	gboolean close = FALSE;

	if ((condition & G_IO_IN) &&
		g_io_channel_read_line(source, &str, NULL, NULL, NULL) ==
							G_IO_STATUS_NORMAL) {
		str[strlen(str) - 1] = '\0';
		connman_warn("protovpn request '%s'", str);

		if (g_str_has_prefix(str, ">PASSWORD:Need 'Auth'")) {
			/*
			 * Request credentials from the user
			 */
			err = request_credentials_input(data);
			if (err != -EINPROGRESS) {
				vpn_provider_indicate_error(data->provider,
					VPN_PROVIDER_ERROR_LOGIN_FAILED);
				close = TRUE;
			}
		} else if (g_str_has_prefix(str,
				">PASSWORD:Verification Failed: 'Auth'")) {
			++data->failed_attempts;
		}

		g_free(str);
	} else if (condition & (G_IO_ERR | G_IO_HUP)) {
		connman_warn("Management channel termination");
		close = TRUE;
	}

	if (close) {
		close_management_interface(data);
	}

	return TRUE;
}

static int ov_management_connect_timer_cb(gpointer user_data)
{
	struct ov_private_data *data = user_data;
	struct sockaddr_un remote;
	int err = 0;

	if (data->mgmt_socket_fd == -1) {
		data->mgmt_socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (data->mgmt_socket_fd == -1) {
			connman_warn("Unable to create management socket");
		}
	}

	if (data->mgmt_socket_fd != -1) {
		memset(&remote, 0, sizeof(remote));
		remote.sun_family = AF_UNIX;
		g_strlcpy(remote.sun_path, data->mgmt_path,
						sizeof(remote.sun_path));

		err = connect(data->mgmt_socket_fd, (struct sockaddr *)&remote,
							sizeof(remote));
		if (err == 0) {
			data->mgmt_channel =
				g_io_channel_unix_new(data->mgmt_socket_fd);
			data->mgmt_event_id = g_io_add_watch(data->mgmt_channel,
					G_IO_IN | G_IO_ERR | G_IO_HUP,
					ov_management_handle_input, data);

			connman_warn("Connected management socket");
			data->mgmt_timer_id = 0;
			return G_SOURCE_REMOVE;
		}
	}

	++data->connect_attempts;
	if (data->connect_attempts > 30) {
		connman_warn("Unable to connect management socket");
		data->mgmt_timer_id = 0;
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}



static int ov_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb, const char *dbus_sender,
			void *user_data)
{
	const char *option;
	struct ov_private_data *data;

	option = vpn_provider_get_string(provider, "Host");
	if (!option) {
		connman_error("Host not set; cannot enable VPN");
		return -EINVAL;
	}

	data = g_try_new0(struct ov_private_data, 1);
	if (!data)
		return -ENOMEM;

	data->provider = provider;
	data->task = task;
	data->dbus_sender = g_strdup(dbus_sender);
	data->if_name = g_strdup(if_name);
	data->cb = cb;
	data->user_data = user_data;
	data->mgmt_path = NULL;
	data->mgmt_timer_id = 0;
	data->mgmt_socket_fd = -1;
	data->mgmt_event_id = 0;
	data->mgmt_channel = NULL;
	data->connect_attempts = 0;
	data->failed_attempts = 0;

	option = vpn_provider_get_string(provider, "ProtoVPN.AuthUserPass");
	if (option && !strcmp(option, "-")) {
		/*
		 * We need to use the management interface to provide
		 * the user credentials
		 */

		/* Set up the path for the management interface */
		data->mgmt_path = g_strconcat("/tmp/connman-vpn-management-",
			vpn_provider_get_string(provider, "Host"), "-", 
			vpn_provider_get_string(provider, "Domain"), NULL);
		if (unlink(data->mgmt_path) != 0 && errno != ENOENT) {
			connman_warn("Unable to unlink management socket %s: %d",
						data->mgmt_path, errno);
		}

		data->mgmt_timer_id = g_timeout_add(200,
					ov_management_connect_timer_cb, data);
	}

	task_append_config_data(provider, task);

	return run_connect(data, cb, user_data);
}

static int ov_device_flags(struct vpn_provider *provider)
{
	const char *option;

	option = vpn_provider_get_string(provider, "ProtoVPN.DeviceType");
	if (!option) {
		return IFF_TUN;
	}

	if (g_str_equal(option, "tap")) {
		return IFF_TAP;
	}

	if (!g_str_equal(option, "tun")) {
		connman_warn("bad ProtoVPN.DeviceType value, falling back to tun");
	}

	return IFF_TUN;
}

/*
 * Handle notifys delivered over D-Bus via Connman.
 */
static int pv_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	connman_info("pv_notify");
	return ov_notify(msg, provider);
}

/*
 * Connect VPN.
 * Get settings from provider using: vpn_provider_get_string().
 * Add arguments to task with connman_task_add_argument().
 * if_name 
 * cb
 * dbus_sender address of the caller
 * user_data 
 */
static int pv_connect(struct vpn_provider *provider, struct connman_task *task,
		const char *if_name, vpn_provider_connect_cb_t cb,
		const char *dbus_sender, void *user_data)
{
	connman_info("pv_connect");
	return ov_connect(provider, task, if_name, cb, dbus_sender, user_data);
}

/*
 * Handle VPN disconnect.
 *
 * Implementation not madnatory.
 */
void pv_disconnect(struct vpn_provider *provider)
{
	connman_info("pv_disconnect");
	return;
}

/*
 * Handle exit/error_code.
 * 
 * Implementation not madnatory.
 */
static int pv_error_code(struct vpn_provider *provider, int exit_code)
{
	connman_info("pv_error_code %d", exit_code);
	return 0;
}

/*
 * Save the VPN configuration to a keyfile.
 *
 * Implementation not madnatory.
 */
static int pv_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	connman_info("pv_save");
	return ov_save(provider, keyfile);
}

/*
 * Function for returning correct device flags (IFF_TUN / IFF_TAP)
 * based on the vpn_provider content.
 * Use vpn_provider_get_string(provider, parameter) to get proper parameter.
 *
 * Implementation not madnatory.
 */
static int pv_device_flags(struct vpn_provider *provider)
{
	connman_info("pv_device_flags");
	return ov_device_flags(provider);
}

/*
 * Function for parsing the enviroment values. If this function is defined it is
 * called by vpn-provider.c:route_env_parse().
 *
 * @provider: vpn_provider structure for this plugin
 * @key: Key to parse
 * @family: Protocol family (AF_INET, AF_INET6)
 * @idx: 
 * @type: type of the provider route, defined as enum vpn_provider_route_type in
 *        connman/vpn/vpn-provider.h. Values: PROVIDER_ROUTE_TYPE_NONE = 0,
 *        PROVIDER_ROUTE_TYPE_MASK = 1, PROVIDER_ROUTE_TYPE_ADDR = 2 and
 *        PROVIDER_ROUTE_TYPE_GW = 3
 *
 * @return: 0 when success
 *
 * Implementation not madnatory.
 * 
*/

int pv_route_env_parse(struct vpn_provider *provider, const char *key,
			int *family, unsigned long *idx, enum vpn_provider_route_type *type)
{
	char *end;
	const char *start;
	
	connman_info("pv_route_env_parse");
	
	if (g_str_has_prefix(key, "route_network_")) {
		start = key + strlen("route_network_");
		*type = VPN_PROVIDER_ROUTE_TYPE_ADDR;
	} else if (g_str_has_prefix(key, "route_netmask_")) {
		start = key + strlen("route_netmask_");
		*type = VPN_PROVIDER_ROUTE_TYPE_MASK;
	} else if (g_str_has_prefix(key, "route_gateway_")) {
		start = key + strlen("route_gateway_");
		*type = VPN_PROVIDER_ROUTE_TYPE_GW;
	} else
		return -EINVAL;

	*family = AF_INET;
	*idx = g_ascii_strtoull(start, &end, 10);

	connman_info("pv_route_env_parse success");
	return 0;
}

/*
 * VPN driver structure, defined in connman/vpn/plugins/vpn.h
 */
static struct vpn_driver vpn_driver = {
/*		.flags				= VPN_FLAG_NO_TUN, predefine flags for plugin */
        .notify         	= pv_notify,
        .connect        	= pv_connect,
        .disconnect			= pv_disconnect,
        .error_code     	= pv_error_code,
        .save           	= pv_save,
        .device_flags   	= pv_device_flags,
        .route_env_parse 	= pv_route_env_parse,
};

/*
 * Initialization of the plugin. If connection to dbus is required use
 * connman_dbus_get_connection()
 */
static int protovpn_init(void)
{
	int rval = 0;
	// name, driver, path
	connman_info("protovpn_init");
	connection = connman_dbus_get_connection();
	rval = vpn_register(PLUGIN_NAME, &vpn_driver, BIN_PATH);
	connman_info("protovpn_init done (%d)", rval);
	return rval;
	
}

/*
 * De-initialization of the plugin.
 */
static void protovpn_exit(void)
{
	connman_info("protovpn_exit");
	vpn_unregister(PLUGIN_NAME);
	dbus_connection_unref(connection);
}

/*
 * Macro to enable the plugin to be loadable by Connman.
 * From: connman/include/plugin.h:
 * CONNMAN_PLUGIN_DEFINE:
 * @name: plugin name
 * @description: plugin description
 * @version: plugin version string
 * @init: init function called on plugin loading
 * @exit: exit function called on plugin removal
 */
CONNMAN_PLUGIN_DEFINE(protovpn, "VPN plugin prototype", CONNMAN_VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, protovpn_init, protovpn_exit);
