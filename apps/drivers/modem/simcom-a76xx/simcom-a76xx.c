/*
 * Copyright (C) 2021 metraTec GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT simcom_a76xx

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(modem_simcom_a76xx, CONFIG_MODEM_LOG_LEVEL);
#include <zephyr/net/offloaded_netdev.h>
#include "net_private.h"

#include <app/drivers/simcom-a76xx.h>

#define SMS_TP_UDHI_HEADER 0x40

static struct k_thread modem_rx_thread;
static struct k_work_q modem_workq;
static struct a76xx_data mdata;
static struct modem_context mctx;
static const struct socket_op_vtable offload_socket_fd_op_vtable;

static struct zsock_addrinfo dns_result;
static struct sockaddr dns_result_addr;
static char dns_result_canonname[DNS_MAX_NAME_SIZE + 1];

static struct a76xx_gnss_data gnss_data;

static K_KERNEL_STACK_DEFINE(modem_rx_stack, CONFIG_MODEM_SIMCOM_A76XX_RX_STACK_SIZE);
static K_KERNEL_STACK_DEFINE(modem_workq_stack, CONFIG_MODEM_SIMCOM_A76XX_RX_WORKQ_STACK_SIZE);
NET_BUF_POOL_DEFINE(mdm_recv_pool, MDM_RECV_MAX_BUF, MDM_RECV_BUF_SIZE, 0, NULL);

/* pin settings */
static const struct gpio_dt_spec power_gpio = GPIO_DT_SPEC_INST_GET(0, mdm_power_gpios);

static void socket_close(struct modem_socket *sock);
static const struct socket_dns_offload offload_dns_ops;

static inline uint32_t hash32(char *str, int len)
{
#define HASH_MULTIPLIER 37
    uint32_t h = 0;
    int i;

    for (i = 0; i < len; ++i)
    {
        h = (h * HASH_MULTIPLIER) + str[i];
    }

    return h;
}

static inline uint8_t *modem_get_mac(const struct device *dev)
{
    struct a76xx_data *data = dev->data;
    uint32_t hash_value;

    data->mac_addr[0] = 0x00;
    data->mac_addr[1] = 0x10;

    /* use IMEI for mac_addr */
    hash_value = hash32(mdata.mdm_imei, strlen(mdata.mdm_imei));

    UNALIGNED_PUT(hash_value, (uint32_t *)(data->mac_addr + 2));

    return data->mac_addr;
}

static int offload_socket(int family, int type, int proto);

/* Setup the Modem NET Interface. */
static void modem_net_iface_init(struct net_if *iface)
{
    const struct device *dev = net_if_get_device(iface);
    struct a76xx_data *data = dev->data;

    net_if_set_link_addr(iface, modem_get_mac(dev), sizeof(data->mac_addr), NET_LINK_ETHERNET);

    data->netif = iface;

    socket_offload_dns_register(&offload_dns_ops);

    net_if_socket_offload_set(iface, offload_socket);
}

/**
 * Changes the operating state of the a76xx.
 *
 * @param state The new state.
 */
static void change_state(enum a76xx_state state)
{
    LOG_DBG("Changing state to (%d)", state);
    mdata.state = state;
}

/**
 * Get the current operating state of the a76xx.
 *
 * @return The current state.
 */
static enum a76xx_state get_state(void)
{
    return mdata.state;
}

/*
 * Parses the +CIPOPEN command and gives back the
 * connect semaphore.
 */
MODEM_CMD_DEFINE(on_cmd_cipopen)
{
    int result = atoi(argv[1]);
    if (result == 0)
    {
        LOG_INF("+CIPOPEN: %d", result);
    }
    else
    {
        LOG_WRN("+CIPOPEN: %d", result);
    }
    modem_cmd_handler_set_error(data, result);
    return 0;
}

/*
 * Unlock the tx ready semaphore if '> ' is received.
 */
MODEM_CMD_DIRECT_DEFINE(on_cmd_tx_ready)
{
    k_sem_give(&mdata.sem_tx_ready);
    return len;
}

MODEM_CMD_DEFINE(on_cmd_netopen)
{
    int error = atoi(argv[0]);
    if (error == 0)
    {
        LOG_INF("+NETOPEN: %d", error);
        modem_cmd_handler_set_error(data, 0);
    }
    else
    {
        LOG_WRN("+NETOPEN: %d", error);
        modem_cmd_handler_set_error(data, -EIO);
    }
    k_sem_give(&mdata.sem_response);
    return 0;
}

MODEM_CMD_DEFINE(on_cmd_ip_error_network_already_opened)
{
    LOG_WRN("+IP ERROR: Network is already opened");
    k_sem_give(&mdata.sem_response);
    return 0;
}

/*
 * Connects an modem socket. Protocol can either be TCP or UDP.
 */
static int offload_connect(void *obj, const struct sockaddr *addr, socklen_t addrlen)
{
    struct modem_socket *sock = (struct modem_socket *)obj;
    // uint16_t dst_port = 0;
    char *protocol;
    // char ip_str[NET_IPV6_ADDR_LEN];
    struct modem_cmd netopen_responses[] = {
        MODEM_CMD("+NETOPEN: ", on_cmd_netopen, 1U, ""),
        MODEM_CMD("+IP ERROR: Network is already opened", on_cmd_ip_error_network_already_opened, 0U, "")};
    struct modem_cmd cipopen_responses[] = {
        MODEM_CMD("+CIPOPEN: ", on_cmd_cipopen, 2U, ",")};
    // longest cipopen command is for TCP. UDP version is significantly shorter
    char cipopen_command[sizeof("AT+CIPOPEN=#,\"TCP\",\"\",#####,0") + NET_IPV6_ADDR_LEN];
    int ret;

    /* Modem is not attached to the network. */
    if (get_state() != A76XX_STATE_NETWORKING)
    {
        return -EAGAIN;
    }

    if (modem_socket_is_allocated(&mdata.socket_config, sock) == false)
    {
        LOG_ERR("Invalid socket id %d from fd %d", sock->id, sock->sock_fd);
        errno = EINVAL;
        return -1;
    }

    if (sock->is_connected == true)
    {
        LOG_ERR("Socket is already connected! id: %d, fd: %d", sock->id, sock->sock_fd);
        errno = EISCONN;
        return -1;
    }

    LOG_DBG("Storing destination address in socket struct");
    sock->dst = *addr;

    // /* get the destination port */
    // if (addr->sa_family == AF_INET6)
    // {
    //     dst_port = ntohs(net_sin6(addr)->sin6_port);
    // }
    // else if (addr->sa_family == AF_INET)
    // {
    //     dst_port = ntohs(net_sin(addr)->sin_port);
    // }

    /* Get protocol */
    protocol = (sock->type == SOCK_STREAM) ? "TCP" : "UDP";

    // ret = modem_context_sprint_ip_addr(addr, ip_str, sizeof(ip_str));
    // if (ret != 0)
    // {
    //     LOG_ERR("Failed to format IP!");
    //     errno = ENOMEM;
    //     return -1;
    // }

    // only works for UDP btw
    ret = snprintk(cipopen_command, sizeof(cipopen_command), "AT+CIPOPEN=%d,\"%s\",,,0", sock->id, protocol);
    if (ret < 0)
    {
        LOG_ERR("Failed to build connect command. ID: %d, FD: %d", sock->id, sock->sock_fd);
        errno = ENOMEM;
        return -1;
    }

    // Starting socket service
    LOG_DBG("Starting socket service...");
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, netopen_responses, ARRAY_SIZE(netopen_responses), "AT+NETOPEN",
                         &mdata.sem_response, MDM_NETOPEN_TIMEOUT);
    if (ret < 0)
    {
        LOG_ERR("Could not start socket service.");
        goto error;
    }

    LOG_DBG("Establishing connection in multisocket mode...");
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, cipopen_responses, ARRAY_SIZE(cipopen_responses), cipopen_command,
                         &mdata.sem_response, MDM_CONNECT_TIMEOUT);
    if (ret < 0)
    {
        LOG_ERR("%s ret: %d", cipopen_command, ret);
        socket_close(sock);
        goto error;
    }

    ret = modem_cmd_handler_get_error(&mdata.cmd_handler_data);
    if (ret != 0)
    {
        LOG_ERR("Closing the socket!");
        socket_close(sock);
        goto error;
    }

    sock->is_connected = true;
    errno = 0;
    return 0;
error:
    //     errno = -ret;
    return -1;
}

/*
 * Send data over a given socket.
 */
static ssize_t offload_sendto(void *obj, const void *buf, size_t len, int flags,
                              const struct sockaddr *dest_addr, socklen_t addrlen)
{
    int ret;
    struct modem_socket *sock = (struct modem_socket *)obj;
    uint16_t dest_port = 0;
    char ip_str[NET_IPV6_ADDR_LEN];
    char cipsend_command[sizeof("AT+CIPSEND=#,#####,\"###.###.###.###\",#####") + NUM_DEC_DIGITS(MDM_MAX_DATA_LENGTH) + NET_IPV6_ADDR_LEN] = {0};
    char ctrlz = 0x1A;

    LOG_DBG("Checking modem network state...");
    if (get_state() != A76XX_STATE_NETWORKING)
    {
        LOG_ERR("Modem currently not attached to the network!");
        return -EAGAIN;
    }

    LOG_DBG("Performing sanity checks on buffer and length...");
    if (!buf || len == 0)
    {
        errno = EINVAL;
        return -1;
    }

    LOG_DBG("Checking if socket is connected...");
    if (!sock->is_connected)
    {
        errno = ENOTCONN;
        return -1;
    }

    /* Only send up to MTU bytes. */
    if (len > MDM_MAX_DATA_LENGTH)
    {
        LOG_DBG("Truncating data length to MDM_MAX_DATA_LENGTH...");
        len = MDM_MAX_DATA_LENGTH;
    }

    LOG_DBG("Getting destination port...");
    if (sock->dst.sa_family == AF_INET6)
    {
        dest_port = ntohs(net_sin6(&sock->dst)->sin6_port);
    }
    else if (sock->dst.sa_family == AF_INET)
    {
        dest_port = ntohs(net_sin(&sock->dst)->sin_port);
    }

    LOG_DBG("Formatting IP address string...");
    ret = modem_context_sprint_ip_addr(&sock->dst, ip_str, sizeof(ip_str));
    if (ret != 0)
    {
        LOG_ERR("Failed to format IP!");
        errno = ENOMEM;
        return -1;
    }

    LOG_DBG("Building CIPSEND command string...");
    ret = snprintk(cipsend_command, sizeof(cipsend_command), "AT+CIPSEND=%d,%d,\"%s\",%d", sock->id, len, ip_str, dest_port);
    if (ret < 0)
    {
        LOG_ERR("Failed to build send command!!");
        errno = ENOMEM;
        return -1;
    }

    LOG_DBG("Taking TX lock semaphore...");
    k_sem_take(&mdata.cmd_handler_data.sem_tx_lock, K_FOREVER);
    k_sem_reset(&mdata.sem_tx_ready);

    /* Send CIPSEND */
    mdata.current_sock_written = len;
    LOG_DBG("Sending AT+CIPSEND command...");
    ret = modem_cmd_send_nolock(&mctx.iface, &mctx.cmd_handler, NULL, 0U, cipsend_command, NULL,
                                K_NO_WAIT);
    if (ret < 0)
    {
        LOG_ERR("Failed to send CIPSEND!");
        goto exit;
    }

    LOG_DBG("Waiting for '>' prompt...");
    ret = k_sem_take(&mdata.sem_tx_ready, K_SECONDS(2));
    if (ret < 0)
    {
        LOG_ERR("Timeout while waiting for tx");
        goto exit;
    }

    LOG_DBG("Sending data payload...");
    modem_cmd_send_data_nolock(&mctx.iface, buf, len);
    LOG_DBG("Sending CTRL-Z terminator...");
    modem_cmd_send_data_nolock(&mctx.iface, &ctrlz, 1);

    // LOG_DBG("Waiting for final OK response...");
    // k_sem_reset(&mdata.sem_response);
    // ret = k_sem_take(&mdata.sem_response, MDM_CMD_TIMEOUT);
    // if (ret < 0)
    // {
    //     LOG_ERR("Timeout waiting for OK");
    // }

exit:
    LOG_DBG("Releasing TX lock semaphore...");
    k_sem_give(&mdata.cmd_handler_data.sem_tx_lock);
    /* Data was successfully sent */

    if (ret < 0)
    {
        errno = -ret;
        return -1;
    }

    //     errno = 0;
    return mdata.current_sock_written;
}

/*
 * Read data from a given socket.
 *
 * Note: len seems to always be zero. It feels like a sanity check more than anything else.
 */
static int sockread_common(int sock_id, struct modem_cmd_handler_data *data, int socket_data_length,
                           uint16_t len, size_t rx_buf_bytes_to_skip)
{
    struct modem_socket *sock;
    struct socket_read_data *sock_data;
    int ret, packet_size;

    if (!len)
    {
        LOG_ERR("Invalid length, aborting");
        return -EAGAIN;
    }

    if (!data->rx_buf)
    {
        LOG_ERR("Incorrect format! Ignoring data!");
        return -EINVAL;
    }

    if (socket_data_length <= 0)
    {
        LOG_ERR("Length error (%d)", socket_data_length);
        return -EAGAIN;
    }

    if (net_buf_frags_len(data->rx_buf) < socket_data_length)
    {
        LOG_DBG("Not enough data -- wait!");
        return -EAGAIN;
    }

    sock = modem_socket_from_id(&mdata.socket_config, sock_id);
    if (!sock)
    {
        LOG_ERR("Socket not found! (%d)", sock_id);
        ret = -EINVAL;
        goto exit;
    }

    sock_data = (struct socket_read_data *)sock->data;
    if (!sock_data)
    {
        LOG_ERR("Socket data not found! (%d)", sock_id);
        ret = -EINVAL;
        goto exit;
    }

    // if (data->rx_buf) {
    // 	dump_net_buf(data->rx_buf);
    // }
    // data->rx_buf = net_buf_skip(data->rx_buf, 2);  // skip /r/n
    // if (data->rx_buf) {
    // 	dump_net_buf(data->rx_buf);
    // }
    data->rx_buf = net_buf_skip(data->rx_buf, rx_buf_bytes_to_skip);
    ret = net_buf_linearize(sock_data->recv_buf, sock_data->recv_buf_len, data->rx_buf, 0, (uint16_t)socket_data_length);
    // ret = net_buf_linearize(sock_data->recv_buf, sock_data->recv_buf_len, data->rx_buf, 0, sock_data->recv_buf_len);
    // mdata.unread_data_lengths[SOCKET_INDEX(sock->id)] = 0;  // if not all data is copied, i honestly dont know what to do
    data->rx_buf = net_buf_skip(data->rx_buf, ret);
    // if (data->rx_buf) {
	// 	dump_net_buf(data->rx_buf);
	// }
    // log sock_data->recv_buf (only log ret characters)
    LOG_HEXDUMP_DBG(sock_data->recv_buf, ret, "Data Copied to App Buffer");
    sock_data->recv_read_len = ret;
    if (ret != socket_data_length)
    {
        LOG_ERR("Total copied data is different then received data!"
                " copied:%d vs. received:%d",
                ret, socket_data_length);
        ret = -EINVAL;
        goto exit;
    } else {
        LOG_DBG("Copied as many bytes as the modem reported (apparently).");
    }

exit:
    /* Indication only sets length to a dummy value. */
    packet_size = modem_socket_next_packet_size(&mdata.socket_config, sock);
    modem_socket_packet_size_update(&mdata.socket_config, sock, -packet_size);
    return ret;
}

MODEM_CMD_DEFINE(on_cmd_ciprxget_mode_2)
{
    // arg format
    // argv[0] -> link number
    // arvg[1] -> bytes read
    // argv[2] -> remaining bytes
    LOG_DBG("on_cmd_ciprxget_mode_2: Args: %s, %s, %s | Arg count: %d", argv[0], argv[1], argv[2], argc);
    // modem_cmd_handler will skip until the last arg
    // which means we need to manually skip the last arg and \r\n
    size_t last_arg_len = strlen(argv[2]);
    size_t rx_buf_bytes_to_skip = last_arg_len + 2;
    int ret = sockread_common(atoi(argv[0]), data, atoi(argv[1]), len, rx_buf_bytes_to_skip);
    return ret;
}

// MODEM_CMD_DEFINE(on_cmd_ciprxget_mode_4)
// {
//     // arg format
//     // argv[0] -> link number
//     // arvg[1] -> data length
//     int socket_id = atoi(argv[0]);
//     size_t data_length = atoi(argv[1]);
//     mdata.unread_data_lengths[SOCKET_INDEX(socket_id)] = data_length;
//     return 0;
// }

/*
 * Read data from a given socket.
 */
static ssize_t offload_recvfrom(void *obj, void *buf, size_t max_len, int flags,
                                struct sockaddr *src_addr, socklen_t *addrlen)
{

    struct modem_socket *sock = (struct modem_socket *)obj;
    char ciprxget_command[sizeof("AT+CIPRXGET=#,#,") + NUM_DEC_DIGITS(MDM_MAX_DATA_LENGTH)];
    int ret, packet_size;
    struct socket_read_data sock_data;

    // struct modem_cmd query_data_length_cmd[] = {MODEM_CMD("+CIPRXGET: 4,", on_cmd_ciprxget_mode_4, 2U, ",")};
    struct modem_cmd get_data_cmd[] = {MODEM_CMD("+CIPRXGET: 2,", on_cmd_ciprxget_mode_2, 3U, ",")};

    LOG_DBG("Receiving data from socket %d...", sock->id);

    LOG_DBG("Checking network state...");
    if (get_state() != A76XX_STATE_NETWORKING)
    {
        LOG_ERR("Modem not in networking state, aborting receive.");
        return -EAGAIN;
    }

    LOG_DBG("Performing sanity checks on buffer and length...");
    if (!buf || max_len == 0)
    {
        errno = EINVAL;
        return -1;
    }

    if (flags & ZSOCK_MSG_PEEK)
    {
        LOG_ERR("MSG_PEEK is not supported.");
        errno = ENOTSUP;
        return -1;
    }

    LOG_DBG("Checking for available data packets...");
    packet_size = modem_socket_next_packet_size(&mdata.socket_config, sock);
    if (!packet_size)
    {
        if (flags & ZSOCK_MSG_DONTWAIT)
        {
            LOG_DBG("No data available and MSG_DONTWAIT is set.");
            errno = EAGAIN;
            return -1;
        }

        LOG_DBG("No data available, waiting for data notification...");
        modem_socket_wait_data(&mdata.socket_config, sock);
        packet_size = modem_socket_next_packet_size(&mdata.socket_config, sock);
        LOG_DBG("Data notification received, packet size is now %d.", packet_size);
    }

    // LOG_DBG("Querying data length");
    // snprintk(ciprxget_command, sizeof(ciprxget_command), "AT+CIPRXGET=4,%d", sock->id);
    // ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, query_data_length_cmd, ARRAY_SIZE(query_data_length_cmd),
    //                      ciprxget_command, &mdata.sem_response, MDM_CIPRXGET_TIMEOUT);

    max_len = (max_len > MDM_MAX_DATA_LENGTH) ? MDM_MAX_DATA_LENGTH : max_len;
    // max_len = (max_len > mdata.unread_data_lengths[SOCKET_INDEX(sock->id)]) ? mdata.unread_data_lengths[SOCKET_INDEX(sock->id)] : max_len;
    LOG_DBG("Building AT+CIPRXGET command to read %zu bytes...", max_len);
    snprintk(ciprxget_command, sizeof(ciprxget_command), "AT+CIPRXGET=2,%d,%zu", sock->id, max_len);

    LOG_DBG("Preparing socket data structure for read...");
    memset(&sock_data, 0, sizeof(sock_data));
    sock_data.recv_buf = buf;
    sock_data.recv_buf_len = max_len;
    sock_data.recv_addr = src_addr;
    sock->data = &sock_data;
    mdata.current_sock_fd = sock->sock_fd;

    LOG_DBG("Sending command '%s' and waiting for response...", ciprxget_command);
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, get_data_cmd, ARRAY_SIZE(get_data_cmd),
                         ciprxget_command, &mdata.sem_response, MDM_CMD_TIMEOUT);
    if (ret < 0)
    {
        LOG_ERR("Failed to receive data, modem_cmd_send returned %d.", ret);
        errno = -ret;
        ret = -1;
        goto exit;
    }

    // /* HACK: use dst address as src */
    // if (src_addr && addrlen)
    // {
    //     LOG_DBG("Copying source address info...");
    //     *addrlen = sizeof(sock->dst);
    //     memcpy(src_addr, &sock->dst, *addrlen);
    // }

    errno = 0;
    ret = sock_data.recv_read_len;
    LOG_DBG("Successfully received %d bytes.", ret);

exit:
    LOG_DBG("Cleaning up socket data...");
    /* clear socket data */
    mdata.current_sock_fd = -1;
    sock->data = NULL;
    return ret;
}

/*
 * Sends messages to the modem.
 */
static ssize_t offload_sendmsg(void *obj, const struct msghdr *msg, int flags)
{
    struct modem_socket *sock = obj;
    ssize_t sent = 0;
    const char *buf;
    size_t len;
    int ret;

    /* Modem is not attached to the network. */
    if (get_state() != A76XX_STATE_NETWORKING)
    {
        LOG_ERR("Modem currently not attached to the network!");
        return -EAGAIN;
    }

    if (sock->type == SOCK_DGRAM)
    {
        /*
         * Current implementation only handles single contiguous fragment at a time, so
         * prevent sending multiple datagrams.
         */
        if (msghdr_non_empty_iov_count(msg) > 1)
        {
            errno = EMSGSIZE;
            return -1;
        }
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        buf = msg->msg_iov[i].iov_base;
        len = msg->msg_iov[i].iov_len;

        while (len > 0)
        {
            ret = offload_sendto(obj, buf, len, flags, msg->msg_name, msg->msg_namelen);
            if (ret < 0)
            {
                if (ret == -EAGAIN)
                {
                    k_sleep(K_SECONDS(1));
                }
                else
                {
                    return ret;
                }
            }
            else
            {
                sent += ret;
                buf += ret;
                len -= ret;
            }
        }
    }

    return sent;
}

/*
 * Closes a given socket.
 */
static void socket_close(struct modem_socket *sock)
{
    char cipclose_cmd_buffer[sizeof("AT+CIPCLOSE=0")];
    int ret;

    LOG_DBG("Closing socket %d...", sock->id);

    LOG_DBG("Building AT+CIPCLOSE command...");
    snprintk(cipclose_cmd_buffer, sizeof(cipclose_cmd_buffer), "AT+CIPCLOSE=%d", sock->id);

    LOG_DBG("Sending command '%s' and waiting for response...", cipclose_cmd_buffer);
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, NULL, 0U, cipclose_cmd_buffer,
                         &mdata.sem_response, MDM_CIPCLOSE_TIMEOUT);
    if (ret < 0)
    {
        LOG_ERR("AT+CIPCLOSE command failed for socket %d, ret: %d", sock->id, ret);
    }

    LOG_DBG("Releasing socket resource for fd %d...", sock->sock_fd);
    modem_socket_put(&mdata.socket_config, sock->sock_fd);
    LOG_DBG("Socket %d closed successfully.", sock->id);
}

/*
 * Offloads read by reading from a given socket.
 */
static ssize_t offload_read(void *obj, void *buffer, size_t count)
{
    return offload_recvfrom(obj, buffer, count, 0, NULL, 0);
}

/*
 * Offloads write by writing to a given socket.
 */
static ssize_t offload_write(void *obj, const void *buffer, size_t count)
{
    return offload_sendto(obj, buffer, count, 0, NULL, 0);
}

/*
 * Offloads close by terminating the connection and freeing the socket.
 */
static int offload_close(void *obj)
{
    struct modem_socket *sock = (struct modem_socket *)obj;

    /* Modem is not attached to the network. */
    if (get_state() != A76XX_STATE_NETWORKING)
    {
        LOG_ERR("Modem currently not attached to the network!");
        return -EAGAIN;
    }

    /* Make sure socket is allocated */
    if (modem_socket_is_allocated(&mdata.socket_config, sock) == false)
    {
        return 0;
    }

    /* Close the socket only if it is connected. */
    if (sock->is_connected)
    {
        socket_close(sock);
    }

    return 0;
}

/*
 * Polls a given socket.
 */
static int offload_poll(struct zsock_pollfd *fds, int nfds, int msecs)
{
    int i;
    void *obj;

    /* Modem is not attached to the network. */
    if (get_state() != A76XX_STATE_NETWORKING)
    {
        LOG_ERR("Modem currently not attached to the network!");
        return -EAGAIN;
    }

    /* Only accept modem sockets. */
    for (i = 0; i < nfds; i++)
    {
        if (fds[i].fd < 0)
        {
            continue;
        }

        /* If vtable matches, then it's modem socket. */
        obj = zvfs_get_fd_obj(fds[i].fd,
                              (const struct fd_op_vtable *)&offload_socket_fd_op_vtable,
                              EINVAL);
        if (obj == NULL)
        {
            return -1;
        }
    }

    return modem_socket_poll(&mdata.socket_config, fds, nfds, msecs);
}

/*
 * Offloads ioctl. Only supported ioctl is poll_offload.
 */
static int offload_ioctl(void *obj, unsigned int request, va_list args)
{
    switch (request)
    {
    case ZFD_IOCTL_POLL_PREPARE:
        return -EXDEV;

    case ZFD_IOCTL_POLL_UPDATE:
        return -EOPNOTSUPP;

    case ZFD_IOCTL_POLL_OFFLOAD:
    {
        /* Poll on the given socket. */
        struct zsock_pollfd *fds;
        int nfds, timeout;

        fds = va_arg(args, struct zsock_pollfd *);
        nfds = va_arg(args, int);
        timeout = va_arg(args, int);

        return offload_poll(fds, nfds, timeout);
    }

    default:
        errno = EINVAL;
        return -1;
    }
}

static const struct socket_op_vtable offload_socket_fd_op_vtable = {
    .fd_vtable = {
        .read = offload_read,
        .write = offload_write,
        .close = offload_close,
        .ioctl = offload_ioctl,
    },
    .bind = NULL,
    .connect = offload_connect,
    .sendto = offload_sendto,
    .recvfrom = offload_recvfrom,
    .listen = NULL,
    .accept = NULL,
    .sendmsg = offload_sendmsg,
    .getsockopt = NULL,
    .setsockopt = NULL,
};

/*
 * Parses the dns response from the modem.
 *
 * Response on success:
 * +CDNSGIP: 1,<domain name>,<IPv4>[,<IPv6>]
 *
 * Response on failure:
 * +CDNSGIP: 0,<err>
 */
MODEM_CMD_DEFINE(on_cmd_cdnsgip)
{
    int state;
    char ips[256];
    size_t out_len;
    int ret = -1;

    state = atoi(argv[0]);
    if (state == 0)
    {
        LOG_ERR("DNS lookup failed with error %s", argv[1]);
        goto exit;
    }

    /* Offset to skip the leading " */
    out_len = net_buf_linearize(ips, sizeof(ips) - 1, data->rx_buf, 1, len);
    ips[out_len] = '\0';

    /* find trailing " */
    char *ipv4 = strstr(ips, "\"");

    if (!ipv4)
    {
        LOG_ERR("Malformed DNS response!!");
        goto exit;
    }

    *ipv4 = '\0';
    net_addr_pton(dns_result.ai_family, ips,
                  &((struct sockaddr_in *)&dns_result_addr)->sin_addr);
    ret = 0;

exit:
    k_sem_give(&mdata.sem_dns);
    return ret;
}

/*
 * Perform a dns lookup.
 */
static int offload_getaddrinfo(const char *node, const char *service,
                               const struct zsock_addrinfo *hints, struct zsock_addrinfo **res)
{
    struct modem_cmd cmd[] = {MODEM_CMD("+CDNSGIP: ", on_cmd_cdnsgip, 2U, ",")};
    char sendbuf[sizeof("AT+CDNSGIP=\"\",##,#####") + 128];
    uint32_t port = 0;
    int ret;

    /* Modem is not attached to the network. */
    if (get_state() != A76XX_STATE_NETWORKING)
    {
        LOG_ERR("Modem currently not attached to the network!");
        return DNS_EAI_AGAIN;
    }

    /* init result */
    (void)memset(&dns_result, 0, sizeof(dns_result));
    (void)memset(&dns_result_addr, 0, sizeof(dns_result_addr));

    /* Currently only support IPv4. */
    dns_result.ai_family = AF_INET;
    dns_result_addr.sa_family = AF_INET;
    dns_result.ai_addr = &dns_result_addr;
    dns_result.ai_addrlen = sizeof(dns_result_addr);
    dns_result.ai_canonname = dns_result_canonname;
    dns_result_canonname[0] = '\0';

    if (service)
    {
        port = atoi(service);
        if (port < 1 || port > USHRT_MAX)
        {
            return DNS_EAI_SERVICE;
        }
    }

    if (port > 0U)
    {
        if (dns_result.ai_family == AF_INET)
        {
            net_sin(&dns_result_addr)->sin_port = htons(port);
        }
    }

    /* Check if node is an IP address */
    if (net_addr_pton(dns_result.ai_family, node,
                      &((struct sockaddr_in *)&dns_result_addr)->sin_addr) == 0)
    {
        *res = &dns_result;
        return 0;
    }

    /* user flagged node as numeric host, but we failed net_addr_pton */
    if (hints && hints->ai_flags & AI_NUMERICHOST)
    {
        return DNS_EAI_NONAME;
    }

    snprintk(sendbuf, sizeof(sendbuf), "AT+CDNSGIP=\"%s\",10,20000", node);
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, cmd, ARRAY_SIZE(cmd), sendbuf,
                         &mdata.sem_dns, MDM_DNS_TIMEOUT);
    if (ret < 0)
    {
        return ret;
    }

    *res = (struct zsock_addrinfo *)&dns_result;
    return 0;
}

/*
 * Free addrinfo structure.
 */
static void offload_freeaddrinfo(struct zsock_addrinfo *res)
{
    /* No need to free static memory. */
    ARG_UNUSED(res);
}

/*
 * DNS vtable.
 */
static const struct socket_dns_offload offload_dns_ops = {
    .getaddrinfo = offload_getaddrinfo,
    .freeaddrinfo = offload_freeaddrinfo,
};

static struct offloaded_if_api api_funcs = {
    .iface_api.init = modem_net_iface_init,
};

static bool offload_is_supported(int family, int type, int proto)
{
    if (family != AF_INET &&
        family != AF_INET6)
    {
        return false;
    }

    if (type != SOCK_DGRAM &&
        type != SOCK_STREAM)
    {
        return false;
    }

    if (proto != IPPROTO_TCP &&
        proto != IPPROTO_UDP)
    {
        return false;
    }

    return true;
}

static int offload_socket(int family, int type, int proto)
{
    int ret;

    ret = modem_socket_get(&mdata.socket_config, family, type, proto);
    if (ret < 0)
    {
        errno = -ret;
        return -1;
    }

    errno = 0;
    return ret;
}

/*
 * Process all messages received from the modem.
 */
static void modem_rx(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    while (true)
    {
        /* Wait for incoming data */
        modem_iface_uart_rx_wait(&mctx.iface, K_FOREVER);

        modem_cmd_handler_process(&mctx.cmd_handler, &mctx.iface);
    }
}

MODEM_CMD_DEFINE(on_cmd_ok)
{
    modem_cmd_handler_set_error(data, 0);
    k_sem_give(&mdata.sem_response);
    return 0;
}

MODEM_CMD_DEFINE(on_cmd_error)
{
    modem_cmd_handler_set_error(data, -EIO);
    k_sem_give(&mdata.sem_response);
    return 0;
}

MODEM_CMD_DEFINE(on_cmd_exterror)
{
    modem_cmd_handler_set_error(data, -EIO);
    k_sem_give(&mdata.sem_response);
    return 0;
}

/*
 * Handles pdp context urc.
 *
 * The urc has the form +APP PDP: <index>,<state>.
 * State can either be ACTIVE for activation or
 * DEACTIVE if disabled.
 */
MODEM_CMD_DEFINE(on_urc_app_pdp)
{
    mdata.pdp_active = strcmp(argv[0], "1") == 0;
    LOG_INF("PDP context active: %u", mdata.pdp_active);
    k_sem_give(&mdata.sem_response);
    return 0;
}

MODEM_CMD_DEFINE(on_urc_ciprxget)
{
    int sock_id = atoi(argv[0]); // link number is equal to socket id
    LOG_DBG("+CIPRXGET: data recieved for socket with ID %d.", sock_id);
    struct modem_socket *socket = modem_socket_from_id(&mdata.socket_config, sock_id);
    if (!socket)
    {
        LOG_ERR("Received data notification for unknown socket ID %d", sock_id);
        return 0;
    }

    LOG_DBG("Data available on socket: %d", sock_id);
    /* Modem does not tell packet size. Set dummy for receive. */
    modem_socket_packet_size_update(&mdata.socket_config, socket, 1);
    modem_socket_data_ready(&mdata.socket_config, socket);
    return 0;
}

MODEM_CMD_DEFINE(on_urc_sms)
{
    LOG_INF("SMS: %s", argv[0]);
    return 0;
}

/*
 * Handles socket data notification.
 *
 * The sim modem sends and unsolicited +CADATAIND: <cid>
 * if data can be read from a socket.
 */
MODEM_CMD_DEFINE(on_urc_cadataind)
{
    struct modem_socket *sock;
    int sock_fd;

    sock_fd = atoi(argv[0]);

    sock = modem_socket_from_fd(&mdata.socket_config, sock_fd);
    if (!sock)
    {
        return 0;
    }

    /* Modem does not tell packet size. Set dummy for receive. */
    modem_socket_packet_size_update(&mdata.socket_config, sock, 1);

    LOG_INF("Data available on socket: %d", sock_fd);
    modem_socket_data_ready(&mdata.socket_config, sock);

    return 0;
}

/*
 * Handles the castate response.
 *
 * +CASTATE: <cid>,<state>
 *
 * Cid is the connection id (socket fd) and
 * state can be:
 *  0 - Closed by remote server or error
 *  1 - Connected to remote server
 *  2 - Listening
 */
MODEM_CMD_DEFINE(on_urc_castate)
{
    struct modem_socket *sock;
    int sockfd, state;

    sockfd = atoi(argv[0]);
    state = atoi(argv[1]);

    sock = modem_socket_from_fd(&mdata.socket_config, sockfd);
    if (!sock)
    {
        return 0;
    }

    /* Only continue if socket was closed. */
    if (state != 0)
    {
        return 0;
    }

    LOG_INF("Socket close indication for socket: %d", sockfd);

    sock->is_connected = false;
    LOG_INF("Socket closed: %d", sockfd);

    return 0;
}

/*
 * Read manufacturer identification.
 */
MODEM_CMD_DEFINE(on_cmd_cgmi)
{
    size_t out_len = net_buf_linearize(
        mdata.mdm_manufacturer, sizeof(mdata.mdm_manufacturer) - 1, data->rx_buf, 0, len);
    mdata.mdm_manufacturer[out_len] = '\0';
    LOG_INF("Manufacturer: %s", mdata.mdm_manufacturer);
    return 0;
}

/*
 * Read model identification.
 */
MODEM_CMD_DEFINE(on_cmd_cgmm)
{
    size_t out_len = net_buf_linearize(mdata.mdm_model, sizeof(mdata.mdm_model) - 1,
                                       data->rx_buf, 0, len);
    mdata.mdm_model[out_len] = '\0';
    LOG_INF("Model: %s", mdata.mdm_model);
    return 0;
}

/*
 * Read software release.
 *
 * Response will be in format RESPONSE: <revision>.
 */
MODEM_CMD_DEFINE(on_cmd_cgmr)
{
    size_t out_len;
    char *p;

    out_len = net_buf_linearize(mdata.mdm_revision, sizeof(mdata.mdm_revision) - 1,
                                data->rx_buf, 0, len);
    mdata.mdm_revision[out_len] = '\0';

    /* The module prepends a Revision: */
    p = strchr(mdata.mdm_revision, ':');
    if (p)
    {
        out_len = strlen(p + 1);
        memmove(mdata.mdm_revision, p + 1, out_len + 1);
    }

    LOG_INF("Revision: %s", mdata.mdm_revision);
    return 0;
}

/*
 * Read serial number identification.
 */
MODEM_CMD_DEFINE(on_cmd_cgsn)
{
    size_t out_len =
        net_buf_linearize(mdata.mdm_imei, sizeof(mdata.mdm_imei) - 1, data->rx_buf, 0, len);
    mdata.mdm_imei[out_len] = '\0';
    LOG_INF("IMEI: %s", mdata.mdm_imei);
    return 0;
}

/*
 * Parses the non urc CREG and updates registration status.
 */
MODEM_CMD_DEFINE(on_cmd_creg)
{
    mdata.mdm_registration = atoi(argv[1]);
    LOG_INF("CREG: %u", mdata.mdm_registration);
    return 0;
}

MODEM_CMD_DEFINE(on_cmd_cpin)
{
    mdata.cpin_ready = strcmp(argv[0], "READY") == 0;
    LOG_INF("CPIN: %d", mdata.cpin_ready);
    return 0;
}

MODEM_CMD_DEFINE(on_cmd_cgatt)
{
    mdata.mdm_cgatt = atoi(argv[0]);
    LOG_INF("CGATT: %d", mdata.mdm_cgatt);
    return 0;
}

/*
 * Handler for RSSI query.
 *
 * +CSQ: <rssi>,<ber>
 *  rssi: 0,-115dBm; 1,-111dBm; 2...30,-110...-54dBm; 31,-52dBm or greater.
 *        99, ukn
 *  ber: Not used.
 */
MODEM_CMD_DEFINE(on_cmd_csq)
{
    int rssi = atoi(argv[0]);

    if (rssi == 0)
    {
        mdata.mdm_rssi = -115;
    }
    else if (rssi == 1)
    {
        mdata.mdm_rssi = -111;
    }
    else if (rssi > 1 && rssi < 31)
    {
        mdata.mdm_rssi = -114 + 2 * rssi;
    }
    else if (rssi == 31)
    {
        mdata.mdm_rssi = -52;
    }
    else
    {
        mdata.mdm_rssi = -1000;
    }

    LOG_INF("RSSI: %d", mdata.mdm_rssi);
    return 0;
}

/*
 * Queries modem RSSI.
 *
 * If a work queue parameter is provided query work will
 * be scheduled. Otherwise rssi is queried once.
 */
static void modem_rssi_query_work(struct k_work *work)
{
    struct modem_cmd cmd[] = {MODEM_CMD("+CSQ: ", on_cmd_csq, 2U, ",")};
    static char *send_cmd = "AT+CSQ";
    int ret;

    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, cmd, ARRAY_SIZE(cmd), send_cmd,
                         &mdata.sem_response, MDM_CMD_TIMEOUT);
    if (ret < 0)
    {
        LOG_ERR("AT+CSQ ret:%d", ret);
    }

    if (work)
    {
        k_work_reschedule_for_queue(&modem_workq, &mdata.rssi_query_work,
                                    K_SECONDS(RSSI_TIMEOUT_SECS));
    }
}

/*
 * Possible responses by the a76xx.
 */
static const struct modem_cmd response_cmds[] = {
    MODEM_CMD("OK", on_cmd_ok, 0U, ""),
    MODEM_CMD("ERROR", on_cmd_error, 0U, ""),
    MODEM_CMD("+CME ERROR: ", on_cmd_exterror, 1U, ""),
    MODEM_CMD_DIRECT(">", on_cmd_tx_ready),
};

/*
 * Possible unsolicited commands.
 */
static const struct modem_cmd unsolicited_cmds[] = {
    MODEM_CMD("+CGEV: ME PDN ACT ", on_urc_app_pdp, 2U, ","),
    MODEM_CMD("+CIPRXGET: 1,", on_urc_ciprxget, 1U, ""),
    // MODEM_CMD("SMS ", on_urc_sms, 1U, ""),
    // MODEM_CMD("+CADATAIND: ", on_urc_cadataind, 1U, ""),
    // MODEM_CMD("+CASTATE: ", on_urc_castate, 2U, ","),
};

/*
 * Activates the pdp context
 */
static int modem_pdp_activate(void)
{
    int counter;
    int ret = 0;

    struct modem_cmd cgatt_cmd[] = {MODEM_CMD("+CGATT: ", on_cmd_cgatt, 1U, "")};
    counter = 0;
    while (counter++ < MDM_MAX_CGATT_WAITS && mdata.mdm_cgatt != 1)
    {
        ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, cgatt_cmd, ARRAY_SIZE(cgatt_cmd), "AT+CGATT?", &mdata.sem_response, MDM_CGATT_TIMEOUT);
        if (ret < 0)
        {
            LOG_ERR("Failed to query cgatt!!");
            return -1;
        }
        k_sleep(K_SECONDS(1));
    }

    if (counter >= MDM_MAX_CGATT_WAITS)
    {
        LOG_WRN("Network attach failed!!");
        return -1;
    }

    if (!mdata.cpin_ready || mdata.mdm_cgatt != 1)
    {
        LOG_ERR("Fatal: Modem is not attached to GPRS network!!");
        return -1;
    }

    LOG_INF("Waiting for network");

    /*
     * Wait until the module is registered to the network.
     * Registration will be set by urc.
     */
    struct modem_cmd cmds[] = {MODEM_CMD("+CREG: ", on_cmd_creg, 2U, ",")};
    counter = 0;
    while (counter++ < MDM_MAX_CEREG_WAITS && mdata.mdm_registration != 1 && mdata.mdm_registration != 5)
    {
        ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, cmds, ARRAY_SIZE(cmds), "AT+CREG?", &mdata.sem_response, MDM_CREG_TIMEOUT);
        if (ret < 0)
        {
            LOG_ERR("Failed to query registration!!");
            return -1;
        }

        k_sleep(K_SECONDS(1));
    }

    if (counter >= MDM_MAX_CEREG_WAITS)
    {
        // mdm_registration was not 1 nor 5 (both are mean registered. See manual for more info.)
        LOG_WRN("Network registration failed!");
        ret = -1;
        goto error;
    }

    // now using just ipv4 (ipv6 not allowed)
    char pdp_config_cmd_buffer[sizeof("AT+CGDCONT=1,\"IP\",\"\"") + CONFIG_MODEM_SIMCOM_A76XX_APN_MAX_LEN];

    snprintk(pdp_config_cmd_buffer,
             sizeof(pdp_config_cmd_buffer),
             "AT+CGDCONT=1,\"IP\",\"%s\"",
             CONFIG_MODEM_SIMCOM_A76XX_APN);
    LOG_DBG("Sending PDP context command: %s", pdp_config_cmd_buffer);
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, NULL, 0, pdp_config_cmd_buffer,
                         &mdata.sem_response, MDM_CMD_TIMEOUT);
    if (ret < 0)
    {
        LOG_ERR("Could not configure pdp context!");
        goto error;
    }

    /*
     * Now activate the pdp context and wait for confirmation.
     */
    LOG_DBG("Attempting to activate PDP context...");
    ret = modem_cmd_send(&mctx.iface, &mctx.cmd_handler, NULL, 0, "AT+CGACT=1,1",
                         &mdata.sem_response, MDM_CMD_TIMEOUT);
    LOG_DBG("Sent AT command to activate PDP context.");

    if (ret < 0)
    {
        LOG_ERR("Could not activate PDP context.");
        goto error;
    }
    ret = k_sem_take(&mdata.sem_response, MDM_PDP_TIMEOUT);

    if (ret < 0)
    {
        LOG_ERR("Timed out waiting for PDP context activation response from modem (ret: %d)", ret);
        ret = -ETIMEDOUT; /* Set a more descriptive error code */
        goto error;
    }
    else if (mdata.pdp_active == false)
    {
        LOG_ERR("PDP context activation was explicitly rejected by the network.");
        ret = -ENETUNREACH; /* Set a more descriptive error code */
        goto error;
    }

    LOG_INF("Network active.");

error:
    return ret;
}

/*
 * Commands to be sent at setup.
 */
static const struct setup_cmd setup_cmds[] = {
    SETUP_CMD_NOHANDLE("ATE0"), // turns off echo mode
    // The four commands below collect product info
    SETUP_CMD("AT+CGMI", "", on_cmd_cgmi, 0U, ""),
    SETUP_CMD("AT+CGMM", "", on_cmd_cgmm, 0U, ""),
    SETUP_CMD("AT+CGMR", "", on_cmd_cgmr, 0U, ""),
    SETUP_CMD("AT+CGSN", "", on_cmd_cgsn, 0U, ""),
    SETUP_CMD_NOHANDLE("AT+CIPRXGET=1"), // lets the received data be called using a link number
#if defined(CONFIG_MODEM_SIM_NUMBERS)
// add setup cmds for sim numbers here
#endif /* defined(CONFIG_MODEM_SIM_NUMBERS) */
#if defined(CONFIG_MODEM_SIMCOM_A76XX_RAT_NB1)
// add setup cmds for NB1 here
#endif /* defined(CONFIG_MODEM_SIMCOM_A76XX_RAT_NB1) */
#if defined(CONFIG_MODEM_SIMCOM_A76XX_RAT_M1)
// add setup cmds for M1 here
#endif /* defined(CONFIG_MODEM_SIMCOM_A76XX_RAT_M1) */
#if defined(CONFIG_MODEM_SIMCOM_A76XX_RAT_GSM)
    // sets preferred mode to GSM
    SETUP_CMD_NOHANDLE("AT+CNMP=13"),
#endif /* defined(CONFIG_MODEM_SIMCOM_A76XX_RAT_GSM) */
    SETUP_CMD("AT+CPIN?", "+CPIN: ", on_cmd_cpin, 1U, ""),
};

/**
 * Decode readable hex to "real" hex.
 */
static uint8_t mdm_pdu_decode_ascii(char byte)
{
    if ((byte >= '0') && (byte <= '9'))
    {
        return byte - '0';
    }
    else if ((byte >= 'A') && (byte <= 'F'))
    {
        return byte - 'A' + 10;
    }
    else if ((byte >= 'a') && (byte <= 'f'))
    {
        return byte - 'a' + 10;
    }
    else
    {
        return 255;
    }
}

/**
 * Reads "byte" from pdu.
 *
 * @param pdu pdu to read from.
 * @param index index of "byte".
 *
 * Sim module "encodes" one pdu byte as two human readable bytes
 * this functions squashes these two bytes into one.
 */
static uint8_t mdm_pdu_read_byte(const char *pdu, size_t index)
{
    return (mdm_pdu_decode_ascii(pdu[index * 2]) << 4 |
            mdm_pdu_decode_ascii(pdu[index * 2 + 1]));
}

/**
 * Decodes time from pdu.
 *
 * @param pdu pdu to read from.
 * @param index index of "byte".
 */
static uint8_t mdm_pdu_read_time(const char *pdu, size_t index)
{
    return (mdm_pdu_decode_ascii(pdu[index * 2]) +
            mdm_pdu_decode_ascii(pdu[index * 2 + 1]) * 10);
}

/**
 * Decode a sms from pdu mode.
 */
static int mdm_decode_pdu(const char *pdu, size_t pdu_len, struct a76xx_sms *target_buf)
{
    size_t index;

    /*
     * GSM_03.38 to Unicode conversion table
     */
    const short enc7_basic[128] = {
        '@', 0xA3, '$', 0xA5, 0xE8, 0xE9, 0xF9, 0xEC, 0xF2, 0xE7,
        '\n', 0xD8, 0xF8, '\r', 0xC5, 0xF8, 0x0394, '_', 0x03A6, 0x0393,
        0x039B, 0x03A9, 0x03A0, 0x03A8, 0x03A3, 0x0398, 0x039E, '\x1b', 0xC6, 0xE6,
        0xDF, 0xC9, ' ', '!', '\"', '#', 0xA4, '%', '&', '\'',
        '(', ')', '*', '+', ',', '-', '.', '/', '0', '1',
        '2', '3', '4', '5', '6', '7', '8', '9', ':', ';',
        '<', '=', '>', '?', 0xA1, 'A', 'B', 'C', 'D', 'E',
        'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
        'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
        'Z', 0xC4, 0xD6, 0xD1, 0xDC, 0xA7, 0xBF, 'a', 'b', 'c',
        'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
        'x', 'y', 'z', 0xE4, 0xF6, 0xF1, 0xFC, 0xE0};

    /* two bytes in pdu are on real byte */
    pdu_len = (pdu_len / 2);

    /* first byte of pdu is length of trailing SMSC information
     * skip it by setting index to SMSC length + 1.
     */
    index = mdm_pdu_read_byte(pdu, 0) + 1;

    if (index >= pdu_len)
    {
        return -1;
    }

    /* read first octet */
    target_buf->first_octet = mdm_pdu_read_byte(pdu, index++);

    if (index >= pdu_len)
    {
        return -1;
    }

    /* pdu_index now points to the address field.
     * first byte of addr field is the addr length -> skip it.
     * address type is not included in addr len -> add +1.
     * address is coded in semi octets
     *  + addr_len/2 if even
     *  + addr_len/2 + 1 if odd
     */
    uint8_t addr_len = mdm_pdu_read_byte(pdu, index);

    index += ((addr_len % 2) == 0) ? (addr_len / 2) + 2 : (addr_len / 2) + 3;

    if (index >= pdu_len)
    {
        return -1;
    }

    /* read protocol identifier */
    target_buf->tp_pid = mdm_pdu_read_byte(pdu, index++);

    if (index >= pdu_len)
    {
        return -1;
    }

    /* read coding scheme */
    uint8_t tp_dcs = mdm_pdu_read_byte(pdu, index++);

    /* parse date and time */
    if ((index + 7) >= pdu_len)
    {
        return -1;
    }

    target_buf->time.year = mdm_pdu_read_time(pdu, index++);
    target_buf->time.month = mdm_pdu_read_time(pdu, index++);
    target_buf->time.day = mdm_pdu_read_time(pdu, index++);
    target_buf->time.hour = mdm_pdu_read_time(pdu, index++);
    target_buf->time.minute = mdm_pdu_read_time(pdu, index++);
    target_buf->time.second = mdm_pdu_read_time(pdu, index++);
    target_buf->time.timezone = mdm_pdu_read_time(pdu, index++);

    /* Read user data length */
    uint8_t tp_udl = mdm_pdu_read_byte(pdu, index++);

    /* Discard header */
    uint8_t header_skip = 0;

    if (target_buf->first_octet & SMS_TP_UDHI_HEADER)
    {
        uint8_t tp_udhl = mdm_pdu_read_byte(pdu, index);

        index += tp_udhl + 1;
        header_skip = tp_udhl + 1;

        if (index >= pdu_len)
        {
            return -1;
        }
    }

    /* Read data according to type set in TP-DCS */
    if (tp_dcs == 0x00)
    {
        /* 7 bit GSM coding */
        uint8_t fill_level = 0;
        uint16_t buf = 0;

        if (target_buf->first_octet & SMS_TP_UDHI_HEADER)
        {
            /* Initial fill because septets are aligned to
             * septet boundary after header
             */
            uint8_t fill_bits = 7 - ((header_skip * 8) % 7);

            if (fill_bits == 7)
            {
                fill_bits = 0;
            }

            buf = mdm_pdu_read_byte(pdu, index++);

            fill_level = 8 - fill_bits;
        }

        uint16_t data_index = 0;

        for (unsigned int idx = 0; idx < tp_udl; idx++)
        {
            if (fill_level < 7)
            {
                uint8_t octet = mdm_pdu_read_byte(pdu, index++);

                buf &= ((1 << fill_level) - 1);
                buf |= (octet << fill_level);
                fill_level += 8;
            }

            /*
             * Convert 7-bit encoded data to Unicode and
             * then to UTF-8
             */
            short letter = enc7_basic[buf & 0x007f];

            if (letter < 0x0080)
            {
                target_buf->data[data_index++] = letter & 0x007f;
            }
            else if (letter < 0x0800)
            {
                target_buf->data[data_index++] = 0xc0 | ((letter & 0x07c0) >> 6);
                target_buf->data[data_index++] = 0x80 | ((letter & 0x003f) >> 0);
            }
            buf >>= 7;
            fill_level -= 7;
        }
        target_buf->data_len = data_index;
    }
    else if (tp_dcs == 0x04)
    {
        /* 8 bit binary coding */
        for (int idx = 0; idx < tp_udl - header_skip; idx++)
        {
            target_buf->data[idx] = mdm_pdu_read_byte(pdu, index++);
        }
        target_buf->data_len = tp_udl;
    }
    else if (tp_dcs == 0x08)
    {
        /* Unicode (16 bit per character) */
        for (int idx = 0; idx < tp_udl - header_skip; idx++)
        {
            target_buf->data[idx] = mdm_pdu_read_byte(pdu, index++);
        }
        target_buf->data_len = tp_udl;
    }
    else
    {
        return -1;
    }

    return 0;
}

/**
 * Check if given char sequence is crlf.
 *
 * @param c The char sequence.
 * @param len Total length of the fragment.
 * @return @c true if char sequence is crlf.
 *         Otherwise @c false is returned.
 */
static bool is_crlf(uint8_t *c, uint8_t len)
{
    /* crlf does not fit. */
    if (len < 2)
    {
        return false;
    }

    return c[0] == '\r' && c[1] == '\n';
}

/**
 * Find terminating crlf in a netbuffer.
 *
 * @param buf The netbuffer.
 * @param skip Bytes to skip before search.
 * @return Length of the returned fragment or 0 if not found.
 */
static size_t net_buf_find_crlf(struct net_buf *buf, size_t skip)
{
    size_t len = 0, pos = 0;
    struct net_buf *frag = buf;

    /* Skip to the start. */
    while (frag && skip >= frag->len)
    {
        skip -= frag->len;
        frag = frag->frags;
    }

    /* Need to wait for more data. */
    if (!frag)
    {
        return 0;
    }

    pos = skip;

    while (frag && !is_crlf(frag->data + pos, frag->len - pos))
    {
        if (pos + 1 >= frag->len)
        {
            len += frag->len;
            frag = frag->frags;
            pos = 0U;
        }
        else
        {
            pos++;
        }
    }

    if (frag && is_crlf(frag->data + pos, frag->len - pos))
    {
        len += pos;
        return len - skip;
    }

    return 0;
}

/*
 * Does the modem setup by starting it and
 * bringing the modem to a PDP active state.
 */
static int modem_setup(void)
{
    int ret = 0;
    int counter = 0;

    LOG_INF("[1/7] Cancelling any pending RSSI query work...");
    k_work_cancel_delayable(&mdata.rssi_query_work);

    // ret = modem_autobaud();
    LOG_INF("[2/7] Powering on modem...");
    ret = mdm_a76xx_power_on();
    if (ret < 0)
    {
        LOG_ERR("Booting modem failed!!");
        goto error;
    }

    LOG_INF("[3/7] Sending initialization commands...");
    ret = modem_cmd_handler_setup_cmds(&mctx.iface, &mctx.cmd_handler, setup_cmds,
                                       ARRAY_SIZE(setup_cmds), &mdata.sem_response,
                                       MDM_REGISTRATION_TIMEOUT);
    if (ret < 0)
    {
        LOG_ERR("Failed to send init commands!");
        goto error;
    }

    LOG_DBG("Sleeping for 3s to let modem stabilize...");
    k_sleep(K_SECONDS(3));

    LOG_INF("[4/7] Checking network signal quality...");
    modem_rssi_query_work(NULL);
    k_sleep(MDM_WAIT_FOR_RSSI_DELAY);

    counter = 0;
    while (counter++ < MDM_WAIT_FOR_RSSI_COUNT &&
           (mdata.mdm_rssi >= 0 || mdata.mdm_rssi <= -1000))
    {
        LOG_DBG("RSSI check %d: %d", counter, mdata.mdm_rssi);
        modem_rssi_query_work(NULL);
        k_sleep(MDM_WAIT_FOR_RSSI_DELAY);
    }

    if (mdata.mdm_rssi >= 0 || mdata.mdm_rssi <= -1000)
    {
        LOG_ERR("Network not reachable!! RSSI=%d", mdata.mdm_rssi);
        ret = -ENETUNREACH;
        goto error;
    }
    LOG_INF("Network reachable, RSSI=%d", mdata.mdm_rssi);

    LOG_INF("[5/7] Activating PDP context...");
    ret = modem_pdp_activate();
    if (ret < 0)
    {
        LOG_ERR("PDP context activation failed: %d", ret);
        goto error;
    }
    LOG_INF("PDP context activated.");

    LOG_INF("[6/7] Scheduling periodic RSSI updates...");
    k_work_reschedule_for_queue(&modem_workq, &mdata.rssi_query_work,
                                K_SECONDS(RSSI_TIMEOUT_SECS));

    LOG_INF("[7/7] Switching modem to NETWORKING state...");
    change_state(A76XX_STATE_NETWORKING);

    LOG_INF("Modem setup complete.");
    return 0;

error:
    LOG_ERR("Modem setup failed at step %d with code: %d", counter, ret);
    return ret;
}

int mdm_a76xx_start_network(void)
{
    change_state(A76XX_STATE_INIT);
    return modem_setup();
}

int mdm_a76xx_power_on(void)
{
    LOG_INF("Powering on A76XX modem...");
    int err = gpio_pin_set_dt(&power_gpio, 1);
    if (err)
    {
        LOG_ERR("Failed to set power pin HIGH: %d", err);
        return err;
    }
    k_sleep(K_SECONDS(60));
    mdata.powered_on = true;
    LOG_INF("A76XX modem powered on.");
    return 0;
}

int mdm_a76xx_power_off(void)
{
    LOG_INF("Powering off A76XX modem...");
    int err = gpio_pin_set_dt(&power_gpio, 0);
    if (err)
    {
        LOG_ERR("Failed to set power pin LOW: %d", err);
        return err;
    }
    k_sleep(K_MSEC(1000));
    mdata.powered_on = false;
    LOG_INF("A76XX modem powered off.");
    return 0;
}

const char *mdm_a76xx_get_manufacturer(void)
{
    return mdata.mdm_manufacturer;
}

const char *mdm_a76xx_get_model(void)
{
    return mdata.mdm_model;
}

const char *mdm_a76xx_get_revision(void)
{
    return mdata.mdm_revision;
}

const char *mdm_a76xx_get_imei(void)
{
    return mdata.mdm_imei;
}

/*
 * Initializes modem handlers and context.
 * After successful init this function calls
 * modem_setup.
 */
static int modem_init(const struct device *dev)
{
    int ret = 0;

    ARG_UNUSED(dev);

    LOG_DBG("Initializing A76XX modem driver...");
    gpio_pin_configure_dt(&power_gpio, GPIO_OPEN_DRAIN | GPIO_OUTPUT_ACTIVE);
    mdm_a76xx_power_off(); // just in case its still on

    LOG_DBG("Initializing semaphores...");
    k_sem_init(&mdata.sem_response, 0, 1);
    k_sem_init(&mdata.sem_tx_ready, 0, 1);
    k_sem_init(&mdata.sem_dns, 0, 1);
    k_sem_init(&mdata.sem_ftp, 0, 1);

    LOG_DBG("Starting workqueue...");
    k_work_queue_start(&modem_workq, modem_workq_stack,
                       K_KERNEL_STACK_SIZEOF(modem_workq_stack), K_PRIO_COOP(7), NULL);

    mdata.mdm_registration = 0;
    mdata.cpin_ready = false;
    mdata.pdp_active = false;

    mdata.sms_buffer = NULL;
    mdata.sms_buffer_pos = 0;

    LOG_DBG("Initializing socket config...");
    ret = modem_socket_init(&mdata.socket_config, &mdata.sockets[0], ARRAY_SIZE(mdata.sockets),
                            MDM_BASE_SOCKET_NUM, true, &offload_socket_fd_op_vtable);
    if (ret < 0)
    {
        LOG_ERR("Initializing socket config failed: %d", ret);
        goto error;
    }

    LOG_DBG("Setting driver state set to INIT...");
    change_state(A76XX_STATE_INIT);

    const struct modem_cmd_handler_config cmd_handler_config = {
        .match_buf = &mdata.cmd_match_buf[0],
        .match_buf_len = sizeof(mdata.cmd_match_buf),
        .buf_pool = &mdm_recv_pool,
        .alloc_timeout = BUF_ALLOC_TIMEOUT,
        .eol = "\r\n",
        .user_data = NULL,
        .response_cmds = response_cmds,
        .response_cmds_len = ARRAY_SIZE(response_cmds),
        .unsol_cmds = unsolicited_cmds,
        .unsol_cmds_len = ARRAY_SIZE(unsolicited_cmds),
    };

    LOG_INF("Initializing command handler...");
    ret = modem_cmd_handler_init(&mctx.cmd_handler, &mdata.cmd_handler_data,
                                 &cmd_handler_config);
    if (ret < 0)
    {
        LOG_ERR("Command handler init failed: %d", ret);
        goto error;
    }

    const struct modem_iface_uart_config uart_config = {
        .rx_rb_buf = &mdata.iface_rb_buf[0],
        .rx_rb_buf_len = sizeof(mdata.iface_rb_buf),
        .dev = MDM_UART_DEV,
        .hw_flow_control = DT_PROP(MDM_UART_NODE, hw_flow_control),
    };

    LOG_INF("Initializing UART interface...");
    ret = modem_iface_uart_init(&mctx.iface, &mdata.iface_data, &uart_config);
    if (ret < 0)
    {
        LOG_ERR("UART interface init failed: %d", ret);
        goto error;
    }

    mdata.current_sock_fd = -1;
    mdata.current_sock_written = 0;

    mdata.ftp.read_buffer = NULL;
    mdata.ftp.nread = 0;
    mdata.ftp.state = A76XX_FTP_CONNECTION_STATE_INITIAL;

    LOG_INF("Registering modem context...");
    ret = modem_context_register(&mctx);
    if (ret < 0)
    {
        LOG_ERR("Modem context registration failed: %d", ret);
        goto error;
    }

    LOG_INF("Creating RX thread...");
    k_thread_create(&modem_rx_thread, modem_rx_stack, K_KERNEL_STACK_SIZEOF(modem_rx_stack),
                    modem_rx, NULL, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

    LOG_INF("Initializing RSSI query work...");
    k_work_init_delayable(&mdata.rssi_query_work, modem_rssi_query_work);

    LOG_INF("Running modem setup...");
    return modem_setup();

error:
    LOG_ERR("Modem init failed with code: %d", ret);
    return ret;
}

/* Register device with the networking stack. */
NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, modem_init, NULL, &mdata, NULL,
                                  CONFIG_MODEM_SIMCOM_A76XX_INIT_PRIORITY, &api_funcs,
                                  MDM_MAX_DATA_LENGTH);

NET_SOCKET_OFFLOAD_REGISTER(simcom_a76xx, CONFIG_MODEM_SIMCOM_A76XX_SOCKET_PRIORITY,
                            AF_INET, offload_is_supported, offload_socket);
