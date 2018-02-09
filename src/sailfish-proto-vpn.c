#define CONNMAN_API_SUBJECT_TO_CHANGE

#define PLUGIN_NAME "protovpn"
#define BIN_PATH "/usr/sbin/openvpn"	// Path to VPN binary

#include <glib.h>
#include <dbus/dbus.h>

#include <linux/if_tun.h> 		// For IFF_TUN/IFF_TAP
 

#include <connman/plugin.h> 		// Connman plugin registration
#include <connman/task.h> 		// Connman binary execution
#include <connman/log.h>		// Connman logging functions

#include <connman/vpn/vpn-external.h> 	// VPN main header

/*
 * Handle notifys delivered over D-Bus via Connman.
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
	return 0;
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
	connman_info("pv_error_code");
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
	return 0;
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
	return IFF_TUN;
}

/*
 * VPN driver structure, defined in connman/vpn/plugins/vpn.h
 */
static struct vpn_driver vpn_driver = {
/*		.flags			= VPN_FLAG_NO_TUN, predefine flags for plugin */
        .notify         = pv_notify,
        .connect        = pv_connect,
        .disconnect		= pv_disconnect,
        .error_code     = pv_error_code,
        .save           = pv_save,
        .device_flags   = pv_device_flags,
};

/*
 * Initialization of the plugin. If connection to dbus is required use
 * connman_dbus_get_connection()
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
