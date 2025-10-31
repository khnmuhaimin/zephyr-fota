
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);
#include <zephyr/kernel.h>
#include <zephyr/net/wifi_mgmt.h>


#define CONFIG_WIFI_SAMPLE_SSD "Openserve-8B43"
#define CONFIG_WIFI_SAMPLE_PSK "RctVkh8VLh"
static struct net_if *sta_iface;
static struct wifi_connect_req_params sta_config;
static struct net_mgmt_event_callback wifi_connection_cb;
static struct net_mgmt_event_callback wifi_ipv4_cb;
static struct k_sem wifi_connection_sem;
static struct k_sem wifi_ip_address_sem;

#define MAX_COAP_MSG_LEN 256
static const char *const test_path[] = {"hello", NULL};

static void wifi_connection_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event, struct net_if *iface)
{
    switch (mgmt_event)
    {
    case NET_EVENT_WIFI_CONNECT_RESULT:
    {
        LOG_INF("Connected to %s", CONFIG_WIFI_SAMPLE_SSID);
        k_sem_give(&wifi_connection_sem);
        break;
    }
    case NET_EVENT_WIFI_DISCONNECT_RESULT:
    {
        LOG_INF("Disconnected from %s", CONFIG_WIFI_SAMPLE_SSID);
        break;
    }
    default:
        break;
    }
}

static void wifi_ipv4_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event, struct net_if *iface)
{
    if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD)
    {
        LOG_DBG("Got an IP address");
        k_sem_give(&wifi_ip_address_sem);
    }
}

static int init_wifi(void)
{
    k_sleep(K_SECONDS(5));
    k_sem_init(&wifi_connection_sem, 0, 1);
    k_sem_init(&wifi_ip_address_sem, 0, 1);
    net_mgmt_init_event_callback(
        &wifi_connection_cb,
        wifi_connection_event_handler,
        NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT);
    net_mgmt_init_event_callback(
        &wifi_ipv4_cb,
        wifi_ipv4_event_handler,
        NET_EVENT_IPV4_ADDR_ADD);
    net_mgmt_add_event_callback(&wifi_connection_cb);
    net_mgmt_add_event_callback(&wifi_ipv4_cb);
    sta_iface = net_if_get_wifi_sta();
    k_sleep(K_SECONDS(5));
}

static int wait_for_wifi(void)
{

    LOG_DBG("Waiting for wifi...");
    k_sem_take(&wifi_connection_sem, K_FOREVER);
    k_sem_take(&wifi_ip_address_sem, K_FOREVER);
}

int connect_to_wifi(void)
{

    init_wifi();
    if (!sta_iface)
    {
        LOG_INF("STA: interface no initialized");
        return -EIO;
    }

    sta_config.ssid = (const uint8_t *)CONFIG_WIFI_SAMPLE_SSID;
    sta_config.ssid_length = sizeof(CONFIG_WIFI_SAMPLE_SSID) - 1;
    sta_config.psk = (const uint8_t *)CONFIG_WIFI_SAMPLE_PSK;
    sta_config.psk_length = sizeof(CONFIG_WIFI_SAMPLE_PSK) - 1;
    sta_config.security = WIFI_SECURITY_TYPE_PSK;
    sta_config.channel = WIFI_CHANNEL_ANY;
    sta_config.band = WIFI_FREQ_BAND_2_4_GHZ;

    LOG_INF("Connecting to SSID: %s\n", sta_config.ssid);

    int ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta_iface, &sta_config,
                       sizeof(struct wifi_connect_req_params));
    if (ret)
    {
        LOG_ERR("Unable to Connect to (%s)", CONFIG_WIFI_SAMPLE_SSID);
    } else {
        wait_for_wifi();
    }

    return ret;
}
