
// ------------------------ START BASIC HELLO A76XX ------------------------>
// #include <stdio.h>
// #include <zephyr/device.h>
// #include <zephyr/kernel.h>
// #include <zephyr/logging/log.h>
// LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);
// #include "app/drivers/simcom-a76xx.h"

// // const struct device *modem = DEVICE_DT_GET(DT_ALIAS(modem));
// // const struct device *modem_uart = DEVICE_DT_GET(DT_ALIAS(modem_uart));

// int main(void)
// {
//     printf("Hello World! %s\n", CONFIG_BOARD_TARGET);

//     // if (!device_is_ready(modem) || !device_is_ready(modem_uart))
//     // {
//     //     printf("ERROR: Modem devices not found or not ready.\n");
//     //     return -1;
//     // }
//     // printf("SUCCESS: Successfully got modem device handle: %s\n", modem->name);

//     while (1) {
//         k_sleep(K_SECONDS(10));
//     }
//     return 0;
// }
// ------------------------ END BASIC HELLO A76XX ------------------------>


#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

#include <errno.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/kernel.h>

#include <zephyr/net/socket.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/udp.h>
#include <zephyr/net/coap.h>

#include "net_private.h"

const struct device *modem = DEVICE_DT_GET(DT_ALIAS(modem));
const struct device *modem_uart = DEVICE_DT_GET(DT_ALIAS(modem_uart));

#define PEER_PORT 5683
#define MAX_COAP_MSG_LEN 256

/* CoAP socket fd */
static int sock;

struct pollfd fds[1];
static int nfds;

/* CoAP Options */
static const char * const test_path[] = { "hello", NULL };

static void wait(void)
{    
    int ret;

    // A good "before" message states the action and the specific resource.
    LOG_DBG("Blocking on poll(), waiting for data on socket fd %d...", fds[0].fd);

    ret = poll(fds, nfds, -1);
    if (ret < 0) {
        LOG_ERR("Error in poll(): %d", errno);
    } else {
        // A good "after" message confirms the action is complete.
        LOG_DBG("Woke up from poll(), events received.");
    }
}

static void prepare_fds(void)
{
	fds[nfds].fd = sock;
	fds[nfds].events = POLLIN;
	nfds++;
}

static int start_coap_client(void)
{
	int ret = 0;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(PEER_PORT);

	inet_pton(AF_INET, "134.102.218.18",
		  &addr.sin_addr);

	sock = socket(addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	} else {
        LOG_DBG("Created socket with fd %d.", sock);
    }

	ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		LOG_ERR("Cannot connect to UDP remote : %d", errno);
		return -errno;
	}

	prepare_fds();

	return 0;
}

static int process_simple_coap_reply(void)
{
	struct coap_packet reply;
	uint8_t *data;
	int rcvd;
	int ret;

    LOG_DBG("Starting to process simple CoAP reply...");

	wait();

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	rcvd = recv(sock, data, MAX_COAP_MSG_LEN, MSG_DONTWAIT);
	if (rcvd == 0) {
		ret = -EIO;
		goto end;
	}

	if (rcvd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
		} else {
			ret = -errno;
		}

		goto end;
	}

	net_hexdump("Response", data, rcvd);

	ret = coap_packet_parse(&reply, data, rcvd, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
	}

    /*
	 * THE FIX: Extract and print the human-readable payload.
	 */
	uint8_t *payload;
	uint16_t payload_len;

	payload = coap_packet_get_payload(&reply, &payload_len);
	if (payload && payload_len > 0) {
		/*
		 * Use the %.*s format specifier to print the payload,
		 * which is not a null-terminated string.
		 */
		LOG_INF("CoAP response payload: %.*s", payload_len, payload);
	} else {
		LOG_WRN("CoAP response has no payload.");
	}

end:
	k_free(data);

	return ret;
}

static int send_simple_coap_request(uint8_t method)
{
	uint8_t payload[] = "payload";
	struct coap_packet request;
	const char * const *p;
	uint8_t *data;
	int r;

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&request, data, MAX_COAP_MSG_LEN,
			     COAP_VERSION_1, COAP_TYPE_CON,
			     COAP_TOKEN_MAX_LEN, coap_next_token(),
			     method, coap_next_id());
	if (r < 0) {
		LOG_ERR("Failed to init CoAP message");
		goto end;
	}

	for (p = test_path; p && *p; p++) {
		r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					      *p, strlen(*p));
		if (r < 0) {
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

	r = send(sock, request.data, request.offset, 0);

end:
	k_free(data);

	return r;
}

static int send_simple_coap_msgs_and_wait_for_reply(void)
{
	uint8_t test_type = 0U;
	int r;

	while (1) {
		switch (test_type) {
		case 0:
			/* Test CoAP GET method */
			LOG_INF("CoAP client GET");
			r = send_simple_coap_request(COAP_METHOD_GET);
			if (r < 0) {
				return r;
			}

			break;
		case 1:
			/* Test CoAP PUT method */
			LOG_INF("CoAP client PUT");
			r = send_simple_coap_request(COAP_METHOD_PUT);
			if (r < 0) {
				return r;
			}

			break;
		case 2:
			/* Test CoAP POST method*/
			LOG_INF("CoAP client POST");
			r = send_simple_coap_request(COAP_METHOD_POST);
			if (r < 0) {
				return r;
			}

			break;
		case 3:
			/* Test CoAP DELETE method*/
			LOG_INF("CoAP client DELETE");
			r = send_simple_coap_request(COAP_METHOD_DELETE);
			if (r < 0) {
				return r;
			}

			break;
		default:
			return 0;
		}

		r = process_simple_coap_reply();
		if (r < 0) {
			return r;
		}

		test_type++;
	}

	return 0;
}

static K_SEM_DEFINE(wait_for_net, 0, 1);

static void event_handler(uint64_t mgmt_event, struct net_if *iface,
                          void *info, size_t info_length,
                          void *user_data)
{
	if (mgmt_event == NET_EVENT_IF_UP) {
		LOG_INF("Network interface is UP! Connection is ready.");
		/* Unblock the main thread now that the network is ready */
		k_sem_give(&wait_for_net);
	}
}

NET_MGMT_REGISTER_EVENT_HANDLER(iface_event_handler, NET_EVENT_IF_UP,
                                event_handler, NULL);


int main(void)
{

	LOG_INF("Waiting for network connection...");
	k_sem_take(&wait_for_net, K_FOREVER);
	LOG_INF("Network connection established.");

	int r;

	LOG_DBG("Start CoAP-client sample");
	r = start_coap_client();
	if (r < 0) {
		goto quit;
	}

	/* GET, PUT, POST, DELETE */
	r = send_simple_coap_msgs_and_wait_for_reply();
	if (r < 0) {
		goto quit;
	}

	/* Close the socket */
	(void)close(sock);

	LOG_DBG("Done");

	return 0;

quit:
	(void)close(sock);

	LOG_ERR("quit");

	return 0;
}
