#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/dhcpv4_server.h>

LOG_MODULE_REGISTER(wifi_initializer, CONFIG_WIFI_INITIALIZER_LOG_LEVEL);

#define NET_EVENT_WIFI_MASK (NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT)

#define WIFI_SSID CONFIG_WIFI_INITIALIZER_SSID
#define WIFI_PSK CONFIG_WIFI_INITIALIZER_PASSWORD

static struct net_if *sta_iface;
static struct wifi_connect_req_params sta_config;
static struct net_mgmt_event_callback cb;

static void wifi_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
			       struct net_if *iface)
{
	switch (mgmt_event) {
	case NET_EVENT_WIFI_CONNECT_RESULT: {
		LOG_INF("Connected to %s", WIFI_SSID);
		break;
	}
	case NET_EVENT_WIFI_DISCONNECT_RESULT: {
		LOG_INF("Disconnected from %s", WIFI_SSID);
		break;
	}
	default:
		break;
	}
}

static int connect_to_wifi(void)
{
    LOG_DBG("Connecting to wifi...");
	if (!sta_iface) {
		LOG_WRN_ONCE("Interface no initialized");
		return -EIO;
	}

	sta_config.ssid = (const uint8_t *)WIFI_SSID;
	sta_config.ssid_length = strlen(WIFI_SSID);
	sta_config.psk = (const uint8_t *)WIFI_PSK;
	sta_config.psk_length = strlen(WIFI_PSK);
	sta_config.security = WIFI_SECURITY_TYPE_PSK;
	sta_config.channel = WIFI_CHANNEL_ANY;
	sta_config.band = WIFI_FREQ_BAND_2_4_GHZ;

	LOG_INF("Connecting to SSID: %s\n", sta_config.ssid);

	int ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta_iface, &sta_config,
			   sizeof(struct wifi_connect_req_params));
	if (ret) {
		LOG_ERR("Unable to Connect to (%s)", WIFI_SSID);
	}

	return ret;
}

int wifi_init_connect(void)
{
	k_sleep(K_SECONDS(5));
	net_mgmt_init_event_callback(&cb, wifi_event_handler, NET_EVENT_WIFI_MASK);
	net_mgmt_add_event_callback(&cb);
	/* Get STA interface in AP-STA mode. */
	sta_iface = net_if_get_wifi_sta();
	connect_to_wifi();
	return 0;
}
