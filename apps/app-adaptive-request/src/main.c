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

    switch (method) {
	case COAP_METHOD_GET:
	case COAP_METHOD_DELETE:
		break;

	case COAP_METHOD_PUT:
	case COAP_METHOD_POST:
		r = coap_packet_append_payload_marker(&request);
		if (r < 0) {
			LOG_ERR("Unable to append payload marker");
			goto end;
		}

		r = coap_packet_append_payload(&request, (uint8_t *)payload,
					       sizeof(payload) - 1);
		if (r < 0) {
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

    connect_to_wifi();
    adaptive_sockets_init();

    int ret = 0;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5683);
    net_addr_pton(AF_INET, "134.102.218.18", &addr.sin_addr);

    int sock = zsock_socket(addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        LOG_ERR("Failed to create UDP socket %d", errno);
        return -sock;
    }
    else
    {
        LOG_DBG("Created socket with fd %d.", sock);
    }

    ret = zsock_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
    {
        LOG_ERR("Cannot connect to UDP remote : %d", errno);
        return -ret;
    }
    else
    {
        LOG_INF("Connected to UDP remote.");
    }

    ret = send_simple_coap_request(sock, COAP_METHOD_GET);
    if (ret < 0)
    {
        LOG_ERR("Failed to send coap request. Error code %d.", ret);
        return ret;
    }
    else
    {
        LOG_INF("Sent coap request successfully");
    }

    ret = process_simple_coap_reply(sock);
    if (ret < 0)
    {
        LOG_ERR("Error process_simple_coap_reply: %d", errno);
    }
    else
    {
        LOG_INF("Processed coap reply correctly.");
    }

    return 0;
}
