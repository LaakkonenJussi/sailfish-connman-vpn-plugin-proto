/*
 *
 *  ConnMan external VPN plugin prototype.
 *
 *  Copyright (C) 2018  Jolla Ltd. All rights reserved.
 *  Contact: jussi.laakkonen@jolla.com
 *
 *  License: propietary
 */

#define CONNMAN_API_SUBJECT_TO_CHANGE

#define PLUGIN_NAME "protovpn"
#define BIN_PATH "/usr/sbin/openvpn"	// Path to VPN binary

#include <glib.h>
#include <dbus/dbus.h>

#include <linux/if_tun.h> 		// For IFF_TUN/IFF_TAP
 

#include <connman/plugin.h> 		// Connman plugin registration
#include <connman/task.h> 		// Connman binary execution
#include <connman/log.h>		// Connman logging functions

#include <connman/vpn/plugins/vpn.h>	// VPN plugin main header
#include <connman/vpn/vpn-agent.h> 	// VPN agent header

/*
 * Handle notifys delivered over D-Bus via Connman.
 *
 * @msg: Message received via D-Bus
 * @provider: vpn_provider structure for this plugin
 *
 * @return: 0 when success
 */
static int pv_notify(DBusMessage *msg, struct vpn_provider *provider)
{
	connman_info("pv_notify");
	return 0;
}

/*
 * Connect VPN.
 * Get settings from provider using: vpn_provider_get_string().
 * Add arguments to task with connman_task_add_argument().
 * 
 * @provider: vpn_provider structure for this plugin
 * @task: connman task to use for executing the binary
 * @if_name: interface name of the VPN plugin
 * @cb: provider callback
 * @dbus_sender: address of the caller
 * @user_data: user specified data
 *
 * @return: 0 when success
 */
static int pv_connect(struct vpn_provider *provider, struct connman_task *task,
		const char *if_name, vpn_provider_connect_cb_t cb,
		const char *dbus_sender, void *user_data)
{
	connman_info("pv_connect");
	return 0;
}

/*
 * Handle VPN disconnect.
 *
 * @provider: vpn_provider structure for this plugin
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
 * @provider: vpn_provider structure for this plugin
 * @exit_code: plugin exit code to handle
 *
 * @return: result of exit_code handling
 * 
 * Implementation not madnatory.
 */
static int pv_error_code(struct vpn_provider *provider, int exit_code)
{
	connman_info("pv_error_code");
	return 0;
}

/*
 * Save the VPN configuration to a keyfile.
 *
 * @provider: vpn_provider structure for this plugin
 * @keyfile: GKeyFile to use for saving
 *
 * Implementation not madnatory.
 */
static int pv_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	connman_info("pv_save");
	return 0;
}

/*
 * Function for returning correct device flags (IFF_TUN / IFF_TAP)
 * based on the vpn_provider content.
 * Use vpn_provider_get_string(provider, parameter) to get proper parameter.
 *
 * @provider: vpn_provider structure for this plugin
 *
 * @return: device flags for this plugin
 *
 * Implementation not madnatory.
 */
static int pv_device_flags(struct vpn_provider *provider)
{
	connman_info("pv_device_flags");
	return IFF_TUN;
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
	connman_info("pv_route_env_parse");
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
 *
 * @return: 0 when success
 */
static int protovpn_init(void)
{
	// name, driver, path
	connman_info("protovpn_init");
	return vpn_register(PLUGIN_NAME, &vpn_driver, BIN_PATH);
}

/*
 * De-initialization of the plugin.
 */
static void protovpn_exit(void)
{
	connman_info("protovpn_exit");
	vpn_unregister(PLUGIN_NAME);
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
