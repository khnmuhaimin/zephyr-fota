/*
 * Copyright (c) 2024 Muhammad Haziq
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

#include <zephyr/kernel.h>
#include <zephyr/net/wifi_mgmt.h>
#include <stdio.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/udp.h>
#include <zephyr/net/coap.h>
#include <zephyr/posix/sys/socket.h>
#include "net_private.h"
#include "adaptive-sockets.h"
#include <zephyr/mgmt/updatehub.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/conn_mgr_monitor.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/device.h>
#include <zephyr/net/net_config.h>

#define CONFIG_WIFI_SAMPLE_SSID "Openserve-8B43"
#define CONFIG_WIFI_SAMPLE_PSK "RctVkh8VLh"
// #define CONFIG_WIFI_SAMPLE_SSID "My Wifi"
// #define CONFIG_WIFI_SAMPLE_PSK "G4JR2H98"
#define UPDATE_SERVER_IP_ADDRESS "52.207.250.14"
#define WIFI_DEV_NODE DT_ALIAS(wifi)
const struct device *wifi_dev = DEVICE_DT_GET(WIFI_DEV_NODE);
static struct net_if *sta_iface;
static struct wifi_connect_req_params sta_config;
static struct net_mgmt_event_callback wifi_connection_cb;
static struct net_mgmt_event_callback wifi_ipv4_cb;
static struct k_sem wifi_connection_sem;
static struct k_sem wifi_ip_address_sem;

// static void print_ip_addr(struct net_if *iface)
// {
//     struct net_if_addr *if_addr;
//     const struct in_addr *gateway;
//     char hr_addr[NET_IPV4_ADDR_LEN];
//     char iface_name[20];

//     if (iface->if_dev->dev->name) {
//         strncpy(iface_name, iface->if_dev->dev->name, sizeof(iface_name) - 1);
//         iface_name[sizeof(iface_name) - 1] = '\0';
//     } else {
//         strncpy(iface_name, "Unknown", sizeof(iface_name));
//     }

//     // 1. Log IP Address
//     if_addr = net_if_get_primary_addr(iface);
//     if (if_addr) {
//         LOG_INF("Interface [%s] IP: %s",
//                 iface_name,
//                 net_addr_ntop(AF_INET, &if_addr->address.in_addr, hr_addr, sizeof(hr_addr)));
//     } else {
//         LOG_WRN("Interface [%s] has no IP address assigned.", iface_name);
//     }

//     // 2. Log Gateway Address
//     gateway = net_if_ipv4_get_gw(iface);
//     if (gateway && gateway->s_addr) {
//         LOG_INF("Interface [%s] GW: %s",
//                 iface_name,
//                 net_addr_ntop(AF_INET, gateway, hr_addr, sizeof(hr_addr)));
//     } else {
//         LOG_WRN("Interface [%s] has NO Gateway assigned.", iface_name);
//     }
// }

static void wifi_connection_event_handler(struct net_mgmt_event_callback *cb, uint64_t mgmt_event, struct net_if *iface)
{
    switch (mgmt_event)
    {
    case NET_EVENT_WIFI_CONNECT_RESULT:
    {
        LOG_INF("Connected to %s", CONFIG_WIFI_SAMPLE_SSID);
        k_sem_give(&wifi_connection_sem);
        // LOG_INF("Gave wifi_connection_sem.");
        // LOG_DBG("wifi_connection_event_handler: default net if is %s.", net_if_get_default()->if_dev->dev->name);
        // int ret = net_config_init_by_iface(iface, "Initializing network", NET_CONFIG_NEED_IPV4,
        //                                    CONFIG_NET_CONFIG_INIT_TIMEOUT * MSEC_PER_SEC);
        // net_config_init_app(wifi_dev, "Initializing network");
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
        // LOG_DBG("Got an IP address");
        // print_ip_addr(net_if_get_wifi_sta());
        k_sem_give(&wifi_ip_address_sem);
        // LOG_INF("Gave wifi_ip_address_sem.");
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
    net_if_set_default(sta_iface);
    k_sleep(K_SECONDS(5));
    return 0;
}

static int connect_to_wifi(void)
{

    if (!sta_iface)
    {
        LOG_ERR("Station interface not initialized.");
        return -EIO;
    }

    sta_config.ssid = (const uint8_t *)CONFIG_WIFI_SAMPLE_SSID;
    sta_config.ssid_length = sizeof(CONFIG_WIFI_SAMPLE_SSID) - 1;
    sta_config.psk = (const uint8_t *)CONFIG_WIFI_SAMPLE_PSK;
    sta_config.psk_length = sizeof(CONFIG_WIFI_SAMPLE_PSK) - 1;
    sta_config.security = WIFI_SECURITY_TYPE_PSK;
    sta_config.channel = WIFI_CHANNEL_ANY;
    sta_config.band = WIFI_FREQ_BAND_2_4_GHZ;

    // LOG_INF("Connecting to SSID: %s\n", sta_config.ssid);

    int ret = net_mgmt(NET_REQUEST_WIFI_CONNECT, sta_iface, &sta_config,
                       sizeof(struct wifi_connect_req_params));
    if (ret)
    {
        // LOG_ERR("Unable to Connect to (%s)", CONFIG_WIFI_SAMPLE_SSID);
    }

    return ret;
}

static int wait_for_wifi(void)
{
    // LOG_DBG("Waiting for wifi...");
    k_sem_take(&wifi_connection_sem, K_FOREVER);
    k_sem_take(&wifi_ip_address_sem, K_FOREVER);
}

#define MAX_COAP_MSG_LEN 256
static const char *const test_path[] = {"hello", NULL};

static int send_simple_coap_request(int sock, uint8_t method)
{
    uint8_t payload[] = "payload";
    struct coap_packet request;
    const char *const *p;
    uint8_t *data;
    int r;

    data = (uint8_t *)k_calloc(MAX_COAP_MSG_LEN, 1);
    if (!data)
    {
        return -ENOMEM;
    }

    r = coap_packet_init(&request, data, MAX_COAP_MSG_LEN,
                         COAP_VERSION_1, COAP_TYPE_CON,
                         COAP_TOKEN_MAX_LEN, coap_next_token(),
                         method, coap_next_id());
    if (r < 0)
    {
        LOG_ERR("Failed to init CoAP message");
        goto end;
    }

    for (p = test_path; p && *p; p++)
    {
        r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
                                      *p, strlen(*p));
        if (r < 0)
        {
            LOG_ERR("Unable add option to request");
            goto end;
        }
    }

    switch (method)
    {
    case COAP_METHOD_GET:
    case COAP_METHOD_DELETE:
        break;

    case COAP_METHOD_PUT:
    case COAP_METHOD_POST:
        r = coap_packet_append_payload_marker(&request);
        if (r < 0)
        {
            LOG_ERR("Unable to append payload marker");
            goto end;
        }

        r = coap_packet_append_payload(&request, (uint8_t *)payload,
                                       sizeof(payload) - 1);
        if (r < 0)
        {
            LOG_ERR("Not able to append payload");
            goto end;
        }

        break;
    default:
        r = -EINVAL;
        goto end;
    }

    net_hexdump("Request", request.data, request.offset);

    r = zsock_send(sock, request.data, request.offset, 0);

end:
    k_free(data);

    return r;
}

static int process_simple_coap_reply(int sock)
{
    struct coap_packet reply;
    uint8_t *data;
    int rcvd;
    int ret;

    LOG_DBG("Starting to process simple CoAP reply...");

    data = (uint8_t *)k_calloc(MAX_COAP_MSG_LEN, 1);
    if (!data)
    {
        LOG_ERR("Failed to allocate memory for storing coap response.");
        return -ENOMEM;
    }

    rcvd = zsock_recv(sock, data, MAX_COAP_MSG_LEN, MSG_DONTWAIT);
    if (rcvd == 0)
    {
        LOG_ERR("Received zero bytes.");
        ret = -EIO;
        goto end;
    }

    // if (rcvd < 0)
    // {
    //     LOG_ERR("Something went wrong when recieving data.");
    //     if (errno == EAGAIN || errno == EWOULDBLOCK)
    //     {
    //         ret = 0;
    //     }
    //     else
    //     {
    //         ret = -errno;
    //     }

    //     goto end;
    // }

    net_hexdump("Response", data, rcvd);

    ret = coap_packet_parse(&reply, data, rcvd, NULL, 0);
    if (ret < 0)
    {
        LOG_ERR("Invalid data received");
    }

    /*
     * THE FIX: Extract and print the human-readable payload.
     */
    uint8_t *payload;
    uint16_t payload_len;

    payload = coap_packet_get_payload(&reply, &payload_len);
    if (payload && payload_len > 0)
    {
        /*
         * Use the %.*s format specifier to print the payload,
         * which is not a null-terminated string.
         */
        LOG_INF("CoAP response payload: %.*s", payload_len, payload);
    }
    else
    {
        LOG_WRN("CoAP response has no payload.");
    }

end:
    k_free(data);

    return ret;
}

int main(void)
{
    k_sleep(K_SECONDS(5));

    /* The image of application needed be confirmed */
    LOG_INF("Confirming the boot image");
    int ret = updatehub_confirm();
    if (ret < 0)
    {
        LOG_ERR("Error to confirm the image!");
    }
    else
    {
        LOG_INF("Confirmed the boot image.");
    }
    k_sleep(K_SECONDS(5));
    init_wifi();
    connect_to_wifi();
    wait_for_wifi();
    LOG_DBG("Initializing adaptive sockets...");
    adaptive_sockets_init();
    LOG_DBG("Starting updatehub...");
    updatehub_autohandler();


    // int i = 1;
    // while (true) {
    //     LOG_DBG("Sending hello request #%d...", i);
    //     ret = 0;
    //     struct sockaddr_in addr;
    //     addr.sin_family = AF_INET;
    //     addr.sin_port = htons(5683);
    //     net_addr_pton(AF_INET, "134.102.218.18", &addr.sin_addr);

    //     int sock = zsock_socket(addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
    //     if (sock < 0)
    //     {
    //         LOG_ERR("Failed to create UDP socket %d", errno);
    //         return -sock;
    //     }
    //     else
    //     {
    //         LOG_DBG("Created socket with fd %d.", sock);
    //     }

    //     ret = zsock_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    //     if (ret < 0)
    //     {
    //         LOG_ERR("Cannot connect to UDP remote : %d", errno);
    //         return -ret;
    //     }
    //     else
    //     {
    //         LOG_INF("Connected to UDP remote.");
    //     }

    //     ret = send_simple_coap_request(sock, COAP_METHOD_GET);
    //     if (ret < 0)
    //     {
    //         LOG_ERR("Failed to send coap request. Error code %d.", ret);
    //         return ret;
    //     }
    //     else
    //     {
    //         LOG_INF("Sent coap request successfully");
    //     }

    //     ret = process_simple_coap_reply(sock);
    //     if (ret < 0)
    //     {
    //         LOG_ERR("Error process_simple_coap_reply: %d", errno);
    //     }
    //     else
    //     {
    //         LOG_INF("Processed coap reply correctly.");
    //     }
    //     zsock_close(sock);
    //     LOG_DBG("Starting to sleep.");
    //     k_msleep(10000);
    //     LOG_DBG("Done sleeping.");
    //     i++;
    // }

    return 0;
}