/*
 *
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2010-2014  BMW Car IT GmbH.
 *  Copyright (C) 2016-2020  Jolla Ltd.
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
	const char *pv_opt;
	char       has_value;
} pv_options[] = {
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

struct pv_private_data {
	struct vpn_provider *provider;
	struct connman_task *task;
	char *dbus_sender;
	char *if_name;
	vpn_provider_connect_cb_t cb;
	void *user_data;
	char *mgmt_path;
	guint mgmt_timer_id;
	guint mgmt_event_id;
	GIOChannel *mgmt_channel;
	int connect_attempts;
	int failed_attempts_privatekey;
};

/*
 * From openvpn.c. Function to finalize the connection in any case. by calling
 * the vpn-provider.c callback.
 */
static void pv_connect_done(struct pv_private_data *data, int err)
{
	if (data && data->cb) {
		vpn_provider_connect_cb_t cb = data->cb;
		void *user_data = data->user_data;

		/* Make sure we don't invoke this callback twice */
		data->cb = NULL;
		data->user_data = NULL;
		cb(data->provider, user_data, err);
	}

	if (!err)
		data->failed_attempts_privatekey = 0;
}

/* From openvpn.c */
static void free_private_data(struct pv_private_data *data)
{
	if (vpn_provider_get_plugin_data(data->provider) == data)
		vpn_provider_set_plugin_data(data->provider, NULL);

	pv_connect_done(data, EIO);
	vpn_provider_unref(data->provider);
	g_free(data->dbus_sender);
	g_free(data->if_name);
	g_free(data->mgmt_path);
	g_free(data);
}

/* From openvpn.c */
struct nameserver_entry {
	int id;
	char *nameserver;
};

/* From openvpn.c */
static struct nameserver_entry *pv_append_dns_entries(const char *key,
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

/* From openvpn.c */
static char *pv_get_domain_name(const char *key, const char *value)
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

/* From openvpn.c */
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

/* From openvpn.c */
static void free_ns_entry(gpointer data)
{
	struct nameserver_entry *entry = data;

	g_free(entry->nameserver);
	g_free(entry);
}

/* From openvpn.c. For reacting to notify coming via script from the VPN */
static int pv_vpn_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	DBusMessageIter iter, dict;
	const char *reason, *key, *value;
	char *address = NULL, *gateway = NULL, *peer = NULL, *netmask = NULL;
	struct connman_ipaddress *ipaddress;
	GSList *nameserver_list = NULL;
	struct pv_private_data *data = vpn_provider_get_plugin_data(provider);

	dbus_message_iter_init(msg, &iter);

	dbus_message_iter_get_basic(&iter, &reason);
	dbus_message_iter_next(&iter);

	if (!provider) {
		connman_error("No provider found");
		return VPN_STATE_FAILURE;
	}

	if (strcmp(reason, "up")) {
		pv_connect_done(data, EIO);
		return VPN_STATE_DISCONNECT;
	}

	/*
	 * Note, this is better done via UI or VPN D-Bus API but can be forced
	 * here as well. "false" = non-default route.
	 */
	//vpn_provider_set_string(provider, "DefaultRoute", "false");

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

		if ((ns_entry = pv_append_dns_entries(key, value)))
			nameserver_list = g_slist_prepend(nameserver_list,
							ns_entry);
		else {
			char *domain = pv_get_domain_name(key, value);
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

	pv_connect_done(data, 0);
	return VPN_STATE_CONNECT;
}

/*
 * From openvpn.c. Save options specific to this VPN only, provider saves
 * provider related 
 */
static int pv_vpn_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(pv_options); i++) {
		if (strncmp(pv_options[i].cm_opt, "ProtoVPN.", 9) == 0) {
			option = vpn_provider_get_string(provider,
							pv_options[i].cm_opt);
			if (!option)
				continue;

			g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					pv_options[i].cm_opt, option);
		}
	}

	return 0;
}

/*
 * From openvpn.c. Add configuration data for task to be used as startup
 * args 
 */
static int task_append_config_data(struct vpn_provider *provider,
					struct connman_task *task)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(pv_options); i++) {
		if (!pv_options[i].pv_opt)
			continue;

		option = vpn_provider_get_string(provider,
					pv_options[i].cm_opt);
		if (!option)
			continue;

		/*
		 * If the AuthUserPass option is "-", provide the input
		 * via management interface
		 */
		if (!strcmp(pv_options[i].cm_opt, "ProtoVPN.AuthUserPass") &&
						!strcmp(option, "-"))
			option = NULL;

		if (connman_task_add_argument(task,
				pv_options[i].pv_opt,
				pv_options[i].has_value ? option : NULL) < 0)
			return -EIO;
	}

	return 0;
}

/* From openvpn.c */
static void close_management_interface(struct pv_private_data *data)
{
	if (data->mgmt_path) {
		if (unlink(data->mgmt_path) && errno != ENOENT)
			connman_warn("Unable to unlink management socket %s: "
						"%d", data->mgmt_path, errno);

		g_free(data->mgmt_path);
		data->mgmt_path = NULL;
	}
	if (data->mgmt_timer_id != 0) {
		g_source_remove(data->mgmt_timer_id);
		data->mgmt_timer_id = 0;
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

/*
 * From openvpn.c. Called when VPN goes down, propagate the call to vpn_died(),
 * if this is not implemented vpn_died() is called directly. This allows neat
 * cleanup of any data related to this connection.
 */
static void pv_died(struct connman_task *task, int exit_code, void *user_data)
{
	struct pv_private_data *data = user_data;

	/* Cancel any pending agent requests */
	connman_agent_cancel(data->provider);

	close_management_interface(data);

	vpn_died(task, exit_code, data->provider);

	free_private_data(data);
}

static int run_connect(struct pv_private_data *data,
			vpn_provider_connect_cb_t cb, void *user_data)
{
	struct vpn_provider *provider = data->provider;
	struct connman_task *task = data->task;
	const char *option;
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

	err = connman_task_run(task, pv_died, data, NULL, NULL, NULL);
	if (err < 0) {
		data->cb = NULL;
		data->user_data = NULL;
		connman_error("openvpn failed to start");
		return -EIO;
	} else {
		/* This lets the caller know that the actual result of
		 * the operation will be reported to the callback */
		return -EINPROGRESS;
	}
}

/* From openvpn.c */
static void quote_credential(GString *line, const char *cred)
{
	if (!line)
		return;

	g_string_append_c(line, '"');

	while (*cred != '\0') {

		switch (*cred) {
		case ' ':
		case '"':
		case '\\':
			g_string_append_c(line, '\\');
			break;
		default:
			break;
		}

		g_string_append_c(line, *cred++);
	}

	g_string_append_c(line, '"');

	return;
}

/* From openvpn.c */
static void return_credentials(struct pv_private_data *data,
				const char *username, const char *password)
{
	GString *reply_string;
	gchar *reply;
	gsize len;

	reply_string = g_string_new(NULL);

	g_string_append(reply_string, "username \"Auth\" ");
	quote_credential(reply_string, username);
	g_string_append_c(reply_string, '\n');

	g_string_append(reply_string, "password \"Auth\" ");
	quote_credential(reply_string, password);
	g_string_append_c(reply_string, '\n');

	len = reply_string->len;
	reply = g_string_free(reply_string, FALSE);

	g_io_channel_write_chars(data->mgmt_channel, reply, len, NULL, NULL);
	g_io_channel_flush(data->mgmt_channel, NULL);

	memset(reply, 0, len);
	g_free(reply);
}

/*
 * From openvpn.c Demonstrates the use of password for password protected
 * private key file
 */
static void return_private_key_password(struct pv_private_data *data,
				const char *privatekeypass)
{
	GString *reply_string;
	gchar *reply;
	gsize len;

	reply_string = g_string_new(NULL);

	g_string_append(reply_string, "password \"Private Key\" ");
	quote_credential(reply_string, privatekeypass);
	g_string_append_c(reply_string, '\n');

	len = reply_string->len;
	reply = g_string_free(reply_string, FALSE);

	g_io_channel_write_chars(data->mgmt_channel, reply, len, NULL, NULL);
	g_io_channel_flush(data->mgmt_channel, NULL);

	memset(reply, 0, len);
	g_free(reply);
}

/* From openvpn.c */
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

/* From openvpn.c */
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

/* From openvpn.c */
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

/* From openvpn.c. Example of how to process request input credentials reply */
static void request_input_credentials_reply(DBusMessage *reply, void *user_data)
{
	struct pv_private_data *data = user_data;
	char *password = NULL;
	char *username = NULL;
	char *key;
	DBusMessageIter iter, dict;
	DBusError error;
	int err = 0;

	DBG("provider %p", data->provider);

	if (!reply) {
		err = ENOENT;
		goto err;
	}

	dbus_error_init(&error);

	/*
	 * Check the error with VPN agent function to get proper code and to
	 * get callback called.
	 */
	err = vpn_agent_check_and_process_reply_error(reply, data->provider,
				data->task, data->cb, data->user_data);
	if (err) {
		/* Ensure cb is called only once */
		data->cb = NULL;
		data->user_data = NULL;
		return;
	}

	if (!vpn_agent_check_reply_has_dict(reply)) {
		err = ENOENT;
		goto err;
	}

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

	if (!password || !username) {
		vpn_provider_indicate_error(data->provider,
					VPN_PROVIDER_ERROR_AUTH_FAILED);
		err = EACCES;
		goto err;
	}

	return_credentials(data, username, password);

	return;

err:
	pv_connect_done(data, err);
}

/* From openvpn.c, demonstrates use of credential input */
static int request_credentials_input(struct pv_private_data *data)
{
	DBusMessage *message;
	const char *path, *agent_sender, *agent_path;
	DBusMessageIter iter;
	DBusMessageIter dict;
	int err;
	void *agent;

	agent = connman_agent_get_info(data->dbus_sender, &agent_sender,
							&agent_path);
	if (!agent || !agent_path)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					VPN_AGENT_INTERFACE,
					"RequestInput");
	if (!message)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = vpn_provider_get_path(data->provider);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);

	if (vpn_provider_get_authentication_errors(data->provider))
		vpn_agent_append_auth_failure(&dict, data->provider, NULL);

	/* Request temporary properties to pass on to protovpn */
	connman_dbus_dict_append_dict(&dict, "ProtoVPN.Username",
					request_input_append_mandatory, NULL);

	connman_dbus_dict_append_dict(&dict, "ProtoVPN.Password",
					request_input_append_password, NULL);

	vpn_agent_append_host_and_name(&dict, data->provider);

	connman_dbus_dict_close(&iter, &dict);

	err = connman_agent_queue_message(data->provider, message,
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

/*
 * From openvpn.c, demonstrates the way how to handle the input for protected 
 * private key.
 */
static void request_input_private_key_reply(DBusMessage *reply,
							void *user_data)
{
	struct pv_private_data *data = user_data;
	const char *privatekeypass = NULL;
	const char *key;
	DBusMessageIter iter, dict;
	DBusError error;
	int err = 0;

	DBG("provider %p", data->provider);

	if (!reply) {
		err = ENOENT;
		goto err;
	}

	dbus_error_init(&error);

	err = vpn_agent_check_and_process_reply_error(reply, data->provider,
				data->task, data->cb, data->user_data);
	if (err) {
		/* Ensure cb is called only once */
		data->cb = NULL;
		data->user_data = NULL;
		return;
	}

	if (!vpn_agent_check_reply_has_dict(reply)) {
		err = ENOENT;
		goto err;
	}

	dbus_message_iter_init(reply, &iter);
	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;

		dbus_message_iter_recurse(&dict, &entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			break;

		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "ProtoVPN.PrivateKeyPassword")) {
			dbus_message_iter_next(&entry);
			if (dbus_message_iter_get_arg_type(&entry)
							!= DBUS_TYPE_VARIANT)
				break;
			dbus_message_iter_recurse(&entry, &value);
			if (dbus_message_iter_get_arg_type(&value)
							!= DBUS_TYPE_STRING)
				break;
			dbus_message_iter_get_basic(&value, &privatekeypass);
			vpn_provider_set_string_hide_value(data->provider,
					key, privatekeypass);

		}

		dbus_message_iter_next(&dict);
	}

	if (!privatekeypass) {
		vpn_provider_indicate_error(data->provider,
					VPN_PROVIDER_ERROR_AUTH_FAILED);
		err = EACCES;
		goto err;
	}

	return_private_key_password(data, privatekeypass);

	return;

err:
	pv_connect_done(data, err);
}

/*
 * From openvpn.c, this is for requesting the private key input in addition
 * to the credential request. This will create a separate dialog to UI.
 *
  * Also contains examples how to use the credential storage via VPN agent.
 */
static int request_private_key_input(struct pv_private_data *data)
{
	DBusMessage *message;
	const char *path, *agent_sender, *agent_path;
	const char *privatekeypass;
	DBusMessageIter iter;
	DBusMessageIter dict;
	int err;
	void *agent;

	/*
	 * First check if this is the second attempt to get the key within
	 * this connection. In such case there has been invalid Private Key
	 * Password and it must be reset, and queried from user.
	 */
	if (data->failed_attempts_privatekey) {
		vpn_provider_set_string_hide_value(data->provider,
					"ProtoVPN.PrivateKeyPassword", NULL);
	} else {
		/* If the encrypted Private key password is kept in memory and
		 * use it first. If authentication fails this is cleared,
		 * likewise it is when connman-vpnd is restarted.
		 */
		privatekeypass = vpn_provider_get_string(data->provider,
					"ProtoVPN.PrivateKeyPassword");
		if (privatekeypass) {
			return_private_key_password(data, privatekeypass);
			goto out;
		}
	}

	agent = connman_agent_get_info(data->dbus_sender, &agent_sender,
							&agent_path);
	if (!agent || !agent_path)
		return -ESRCH;

	message = dbus_message_new_method_call(agent_sender, agent_path,
					VPN_AGENT_INTERFACE, "RequestInput");
	if (!message)
		return -ENOMEM;

	dbus_message_iter_init_append(message, &iter);

	path = vpn_provider_get_path(data->provider);
	dbus_message_iter_append_basic(&iter,DBUS_TYPE_OBJECT_PATH, &path);

	connman_dbus_dict_open(&iter, &dict);

	connman_dbus_dict_append_dict(&dict, "ProtoVPN.PrivateKeyPassword",
					request_input_append_password, NULL);

	vpn_agent_append_host_and_name(&dict, data->provider);

	/* Do not allow to store or retrieve the encrypted Private Key pass */
	vpn_agent_append_allow_credential_storage(&dict, false);
	vpn_agent_append_allow_credential_retrieval(&dict, false);
	/*
	 * Indicate to keep credentials, the enc Private Key password should not
	 * affect the credential storing.
	 */
	vpn_agent_append_keep_credentials(&dict, true);

	connman_dbus_dict_append_dict(&dict, "Enter Private Key password",
			request_input_append_informational, NULL);

	connman_dbus_dict_close(&iter, &dict);

	err = connman_agent_queue_message(data->provider, message,
			connman_timeout_input_request(),
			request_input_private_key_reply, data, agent);

	if (err < 0 && err != -EBUSY) {
		DBG("error %d sending agent request", err);
		dbus_message_unref(message);

		return err;
	}

	dbus_message_unref(message);

out:
	return -EINPROGRESS;
}

/* From openvpn.c */
static gboolean pv_vpn_management_handle_input(GIOChannel *source,
				GIOCondition condition, gpointer user_data)
{
	struct pv_private_data *data = user_data;
	char *str = NULL;
	int err = 0;
	gboolean close = FALSE;

	if ((condition & G_IO_IN) &&
		g_io_channel_read_line(source, &str, NULL, NULL, NULL) ==
							G_IO_STATUS_NORMAL) {
		str[strlen(str) - 1] = '\0';
		connman_warn("protovpn request %s", str);

		if (g_str_has_prefix(str, ">PASSWORD:Need 'Auth'")) {
			/*
			 * Request credentials from the user
			 */
			err = request_credentials_input(data);
			if (err != -EINPROGRESS)
				close = TRUE;
		} else if (g_str_has_prefix(str,
				">PASSWORD:Need 'Private Key'")) {
			err = request_private_key_input(data);
			if (err != -EINPROGRESS)
				close = TRUE;
		} else if (g_str_has_prefix(str,
				">PASSWORD:Verification Failed: 'Auth'")) {
			/*
			 * This makes it possible to add error only without
			 * sending a state change indication signal to the VPN.
			*/
			vpn_provider_add_error(data->provider,
					VPN_PROVIDER_ERROR_AUTH_FAILED);
		} else if (g_str_has_prefix(str, ">PASSWORD:Verification "
				"Failed: 'Private Key'")) {
			data->failed_attempts_privatekey++;
		}

		g_free(str);
	} else if (condition & (G_IO_ERR | G_IO_HUP)) {
		connman_warn("Management channel termination");
		close = TRUE;
	}

	if (close)
		close_management_interface(data);

	return TRUE;
}

/* From openvpn.c */
static int pv_vpn_management_connect_timer_cb(gpointer user_data)
{
	struct pv_private_data *data = user_data;

	if (!data->mgmt_channel) {
		int fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd >= 0) {
			struct sockaddr_un remote;
			int err;

			memset(&remote, 0, sizeof(remote));
			remote.sun_family = AF_UNIX;
			g_strlcpy(remote.sun_path, data->mgmt_path,
						sizeof(remote.sun_path));

			err = connect(fd, (struct sockaddr *)&remote,
						sizeof(remote));
			if (err == 0) {
				data->mgmt_channel = g_io_channel_unix_new(fd);
				data->mgmt_event_id =
					g_io_add_watch(data->mgmt_channel,
						G_IO_IN | G_IO_ERR | G_IO_HUP,
						pv_vpn_management_handle_input,
						data);

				connman_warn("Connected management socket");
				data->mgmt_timer_id = 0;
				return G_SOURCE_REMOVE;
			}
			close(fd);
		}
	}

	data->connect_attempts++;
	if (data->connect_attempts > 30) {
		connman_warn("Unable to connect management socket");
		data->mgmt_timer_id = 0;
		return G_SOURCE_REMOVE;
	}

	return G_SOURCE_CONTINUE;
}

/* From openvpn.c */
static int pv_vpn_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb, const char *dbus_sender,
			void *user_data)
{
	const char *tmpdir;
	struct pv_private_data *data;

	data = g_try_new0(struct pv_private_data, 1);
	if (!data)
		return -ENOMEM;

	vpn_provider_set_plugin_data(provider, data);
	data->provider = vpn_provider_ref(provider);
	data->task = task;
	data->dbus_sender = g_strdup(dbus_sender);
	data->if_name = g_strdup(if_name);
	data->cb = cb;
	data->user_data = user_data;

	/*
	 * This demonstrates how it is recommended to setup a management
	 * interface for a VPN. It is for reacting to control data coming from
	 * the VPN, as well as possibly sending data to the VPN.
	 */

	/* Use env TMPDIR for creating management socket, fall back to /tmp */
	tmpdir = getenv("TMPDIR");
	if (!tmpdir || !*tmpdir)
		tmpdir = "/tmp";

	/*
	 * Set up the path for the management interface.
	 *
	 * TODO: In 3.4.0 replace both vpn_provider_get_string() with one
	 * vpn_provider_get_ident(provider) call.
	*/
	data->mgmt_path = g_strconcat(tmpdir, "/connman-vpn-management-",
				vpn_provider_get_string(provider, "Name"), "-",
				vpn_provider_get_string(provider, "Host"),
				NULL);

	/* Remove the old management interface if it exists */
	if (unlink(data->mgmt_path) != 0 && errno != ENOENT) {
		connman_warn("Unable to unlink management socket %s: %d",
					data->mgmt_path, errno);
	}

	/* Setup periodic check */
	data->mgmt_timer_id = g_timeout_add(200,
				pv_vpn_management_connect_timer_cb, data);

	task_append_config_data(provider, task);

	return run_connect(data, cb, user_data);
}

/*
 * Handle notifys delivered over D-Bus via Connman.
 */
static int pv_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	connman_info("pv_notify");
	return pv_vpn_notify(msg, provider);
}

/*
 * Connect VPN.
 * Get settings from provider using: vpn_provider_get_string().
 * Add arguments to task with connman_task_add_argument().
 *   if_name      interface to use for connect attempt
 *   cb           connect callback (vpn-provider.c)
 *   dbus_sender  address of the caller
 *   user_data    additional data passed by vpn-provider.c
 */
static int pv_connect(struct vpn_provider *provider, struct connman_task *task,
			const char *if_name, vpn_provider_connect_cb_t cb,
			const char *dbus_sender, void *user_data)
{
	connman_info("pv_connect");
	return pv_vpn_connect(provider, task, if_name, cb, dbus_sender,
								user_data);
}

/*
 * Handle VPN disconnect.
 *
 * Implementation not madnatory but may be useful if functionality is close
 * to, e.g., OpenVPN.
 */
void pv_disconnect(struct vpn_provider *provider)
{
	if (!provider)
		return;

	connman_info("pv_disconnect");

	connman_agent_cancel(provider);

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
 * Save the VPN configuration to a keyfile for this specific VPN type. Provider
 * saves provider related configuration options.
 *
 * Implementation not madnatory if there is no specific options.
 */
static int pv_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	connman_info("pv_save");
	return pv_vpn_save(provider, keyfile);
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
	const char *option;

	connman_info("pv_device_flags");

	option = vpn_provider_get_string(provider, "ProtoVPN.DeviceType");
	if (!option)
		return IFF_TUN;

	if (g_str_equal(option, "tap"))
		return IFF_TAP;

	if (!g_str_equal(option, "tun"))
		connman_warn("bad ProtoVPN.DeviceType value, fallback to tun");

	return IFF_TUN;
}

/*
 * Function for parsing the enviroment values. If this function is defined it
 * is called by vpn-provider.c:route_env_parse().
 *
 * @provider: vpn_provider structure for this plugin
 * @key: Key to parse
 * @family: Protocol family (AF_INET, AF_INET6)
 * @idx: 
 * @type: type of the provider route, defined as enum vpn_provider_route_type
 *        in connman/vpn/vpn-provider.h. Values: PROVIDER_ROUTE_TYPE_NONE = 0,
 *        PROVIDER_ROUTE_TYPE_MASK = 1, PROVIDER_ROUTE_TYPE_ADDR = 2 and
 *        PROVIDER_ROUTE_TYPE_GW = 3
 *
 * @return: 0 when success
 *
 * Implementation not madnatory.
 * 
*/

int pv_route_env_parse(struct vpn_provider *provider, const char *key,
					int *family, unsigned long *idx,
					enum vpn_provider_route_type *type)
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
/*	.flags			= VPN_FLAG_NO_TUN, predefine flags for plugin */
	.notify			= pv_notify,
	.connect		= pv_connect,
	.disconnect		= pv_disconnect,
	.error_code		= pv_error_code,
	.save			= pv_save,
	.device_flags		= pv_device_flags,
	.route_env_parse	= pv_route_env_parse,
};

/*
 * Initialization of the plugin. If connection to dbus is required use
 * connman_dbus_get_connection()
 */
static int protovpn_init(void)
{
	int rval = 0;
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
