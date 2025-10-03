/*
 * Copyright (c) 2018-2023 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/mgmt/updatehub.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>

#ifdef CONFIG_NET_L2_WIFI_MGMT
#include <zephyr/net/wifi_mgmt.h>
#endif /* CONFIG_NET_L2_WIFI_MGMT */

#if defined(CONFIG_UPDATEHUB_DTLS)
#include <zephyr/net/tls_credentials.h>
#include "c_certificates.h"
#endif

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main);

void start_updatehub(void)
{
#if defined(CONFIG_UPDATEHUB_SAMPLE_POLLING)
    LOG_INF("Starting UpdateHub polling mode");
    updatehub_autohandler();
#endif

#if defined(CONFIG_UPDATEHUB_SAMPLE_MANUAL)
    LOG_INF("Starting UpdateHub manual mode");

    switch (updatehub_probe())
    {
    case UPDATEHUB_HAS_UPDATE:
        switch (updatehub_update())
        {
        case UPDATEHUB_OK:
            ret = 0;
            updatehub_reboot();
            break;

        default:
            LOG_ERR("Error installing update.");
            break;
        }

    case UPDATEHUB_NO_UPDATE:
        LOG_INF("No update found");
        ret = 0;
        break;

    default:
        LOG_ERR("Invalid response");
        break;
    }
#endif
}

#define NET_EVENT_WIFI_MASK (NET_EVENT_WIFI_CONNECT_RESULT | NET_EVENT_WIFI_DISCONNECT_RESULT)

/* STA Mode Configuration */
#define WIFI_SSID "My Wifi" /* Replace `SSID` with WiFi ssid. */
#define WIFI_PSK "G4JR2H98" /* Replace `PASSWORD` with Router password. */

static struct net_if *sta_iface;
static struct wifi_connect_req_params sta_config;
static struct net_mgmt_event_callback cb;

static void wifi_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event,
                               struct net_if *iface)
{
    switch (mgmt_event)
    {
    case NET_EVENT_WIFI_CONNECT_RESULT:
    {
        LOG_INF("Connected to %s", WIFI_SSID);
        k_sleep(K_SECONDS(5));
        start_updatehub();
        break;
    }
    case NET_EVENT_WIFI_DISCONNECT_RESULT:
    {
        LOG_INF("Disconnected from %s", WIFI_SSID);
        break;
    }
    default:
        break;
    }
}

static int connect_to_wifi(void)
{
    if (!sta_iface)
    {
        LOG_INF("STA: interface not initialized");
        return -EIO;
    }

    sta_config.ssid = (const uint8_t *)WIFI_SSID;
    sta_config.ssid_length = strlen(WIFI_SSID);
    sta_config.psk = (const uint8_t *)WIFI_PSK;
    sta_config.psk_length = strlen(WIFI_PSK);
    sta_config.security = WIFI_SECURITY_TYPE_PSK;
    sta_config.channel = WIFI_CHANNEL_ANY;
    sta_config.band = WIFI_FREQ_BAND_2_4_GHZ;

    LOG_INF("Connecting to SSID: %s", sta_config.ssid);

    int ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta_iface, &sta_config,
                       sizeof(struct wifi_connect_req_params));
    if (ret)
    {
        LOG_ERR("Unable to Connect to (%s)", WIFI_SSID);
    }

    return ret;
}

int main(void)
{
    /* The image of application needed be confirmed */
    LOG_INF("Confirming the boot image");
    int ret = updatehub_confirm();
    if (ret < 0)
    {
        LOG_ERR("Error to confirm the image");
    }

    k_sleep(K_SECONDS(5));

    net_mgmt_init_event_callback(&cb, wifi_event_handler, NET_EVENT_WIFI_MASK);
    net_mgmt_add_event_callback(&cb);

    /* Get STA interface */
    sta_iface = net_if_get_wifi_sta();

    connect_to_wifi();

    /* Wait forever */
    while (1)
    {
        LOG_DBG("Still alive");
        k_sleep(K_SECONDS(10));
    }

    return 0;
}
