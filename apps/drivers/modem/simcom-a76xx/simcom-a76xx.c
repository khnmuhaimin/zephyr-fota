#define DT_DRV_COMPAT simcom_a76xx

#include <zephyr/logging/log.h>
#include <zephyr/net/offloaded_netdev.h>
#include <zephyr/net/socket.h>
#include <app/drivers/eee4022s_a76xx.h>

LOG_MODULE_REGISTER(a76xx, CONFIG_MODEM_LOG_LEVEL);

static void a76xx_init_net_if(struct net_if *iface);
static int a76xx_enable_net_if(const struct net_if *iface, bool state);
static enum offloaded_net_if_types a76xx_net_if_get_type(void);

static struct a76xx_data_t a76xx_data;
static struct offloaded_if_api api_funcs = {
    .iface_api.init = a76xx_init_net_if,
    .enable = a76xx_enable_net_if,
    .get_type = a76xx_net_if_get_type};

static void a76xx_init_net_if(struct net_if *iface)
{
    LOG_DBG("Calling a76xx_init_net_if...");
}

static int a76xx_enable_net_if(const struct net_if *iface, bool state)
{
    LOG_DBG("Calling a76xx_enable_net_if...");
}

static enum offloaded_net_if_types a76xx_net_if_get_type(void)
{
    LOG_DBG("Calling a76xx_net_if_get_type...");
    return L2_OFFLOADED_NET_IF_TYPE_MODEM;
}

static int a76xx_init(const struct device *dev)
{
    LOG_DBG("Calling a76xx_init...");
}

int a76xx_power_on(void)
{
    LOG_DBG("Calling a76xx_power_on...");
    return 0;
}

int a76xx_power_off(void)
{
    LOG_DBG("Calling a76xx_power_off...");
    return 0;
}

int a76xx_start_network(void)
{
    LOG_DBG("Calling a76xx_start_network...");
    return 0;
}

const char *a76xx_get_manufacturer(void)
{
    LOG_DBG("Calling a76xx_get_manufacturer...");
    return "SIMCOM";
}

const char *a76xx_get_model(void)
{
    LOG_DBG("Calling a76xx_get_model...");
    return "a76xx";
}

const char *a76xx_get_revision(void)
{
    LOG_DBG("Calling a76xx_get_revision...");
    return "1.0.0";
}

const char *a76xx_get_imei(void)
{
    LOG_DBG("Calling a76xx_get_imei...");
    return "123456789012345";
}

static bool a76xx_offload_is_supported(int family, int type, int proto)
{
	if (family != AF_INET &&
	    family != AF_INET6) {
		return false;
	}

	if (type != SOCK_DGRAM &&
	    type != SOCK_STREAM) {
		return false;
	}

	if (proto != IPPROTO_TCP &&
	    proto != IPPROTO_UDP) {
		return false;
	}

	return true;
}

static int a76xx_get_socket(int family, int type, int proto)
{
	int ret;

	ret = modem_socket_get(&a76xx_data.socket_config, family, type, proto);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	errno = 0;
	return ret;
}

NET_DEVICE_DT_INST_OFFLOAD_DEFINE(
    0,
    a76xx_init,
    NULL,
    a76xx_data,
    NULL,
    CONFIG_MODEM_SIMCOM_A76XX_INIT_PRIORITY,
    &api_funcs,
    A76XX_MAX_DATA_LENGTH);

NET_SOCKET_OFFLOAD_REGISTER(
    a76xx,
    CONFIG_NET_SOCKETS_OFFLOAD_PRIORITY,
    AF_UNSPEC,
    a76xx_offload_is_supported,
    a76xx_get_socket);
