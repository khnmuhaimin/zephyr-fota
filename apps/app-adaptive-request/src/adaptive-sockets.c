#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(adaptive_sockets, LOG_LEVEL_DBG);
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>

// node identifiers
#define ADAPT_NET_DEV_1 DT_ALIAS(adaptive_net_device_1)
#define ADAPT_NET_DEV_2 DT_ALIAS(adaptive_net_device_2)

// compile time checks
#if !DT_NODE_HAS_STATUS(ADAPT_NET_DEV_1, okay)
#error "Devicetree alias 'adaptive-net-device-1' is missing or disabled. Please define it in your board overlay."
#endif
#if !DT_NODE_HAS_STATUS(ADAPT_NET_DEV_2, okay)
#error "Devicetree alias 'adaptive-net-device-2' is missing or disabled. Please define it in your board overlay."
#endif

#define NET_IF_STATUS_POLLING_INTERVAL K_SECONDS(10)
#define NET_IF_STATUS_POLLING_PRIORITY 10
#define NET_IF_1_STABLE_CHECKS_NEEDED 2
#define ADAPTIVE_MAX_SEND_TRIES 3
#define ADAPTIVE_MAX_RECV_TRIES 3

/*
 * Holds data for and Adaptive Socket
 */
struct adaptive_socket
{
    int fd;
    struct netif *net_if;
    struct net_context *context;
    struct k_sem recv_pkt_sem;
    struct net_pkt *recv_pkt;
    struct sockaddr *dest_addr;
    socklen_t dest_addr_len;
    uint8_t *send_buf;
    size_t send_buf_len;
    bool connected;
    int error;
};

/*
 * Holds data for the Adaptive Sockets Layer
 */
struct adaptive_sockets_layer
{
    struct net_if *net_if_1;
    struct net_if *net_if_2;
    bool net_if_1_operational;
    bool net_if_2_operational;
    /*
     * Keeps track of how many recent checks found net if 1 to be stable.
     * Gets reset to 0 if net if 1 is not operational.
     * Increases by 1 every time net if 1 is found operational.
     * Capped at NET_IF_1_STABLE_CHECKS_NEEDED.
     * net if 1 is stable if net_if_1_successful_stable_checks == NET_IF_1_STABLE_CHECKS_NEEDED.
     */
    uint8_t net_if_1_successful_stable_checks;
    struct k_mutex lock;
    struct k_thread monitor_thread_data;
    k_tid_t monitor_tid;
    int error;
};

void net_if_status_monitor_thread(void *p1, void *p2, void *p3);
K_THREAD_STACK_DEFINE(monitor_stack_area, NET_IF_STATUS_MONITOR_THREAD_STACK_SIZE);
static struct adaptive_sockets_layer adapt_sockets_layer = {0};
static bool adaptive_net_if_is_operational(struct net_if *iface);
static int adaptive_close(void *obj);
static int adaptive_connect(void *obj, const struct sockaddr *dest_addr, socklen_t dest_addr_len);
static ssize_t adaptive_sendto(void *obj, const void *buf, size_t buf_len, int flags, struct sockaddr *dest_addr, socklen_t dest_addr_len);
static ssize_t adaptive_recvfrom(void *obj, void *buf, size_t buf_len, int flags, struct sockaddr *src_addr, socklen_t *src_addr_len);

static const struct socket_op_vtable adapt_socket_ops = {
    .fd_vtable = {
        .read = NULL,
        .write = NULL,
        .close = adaptive_close, // implement
        .ioctl = NULL},
    .shutdown = NULL,
    .bind = NULL,
    .connect = adaptive_connect, // implement
    .listen = NULL,
    .accept = NULL,
    .sendto = adaptive_sendto,     // implement
    .recvfrom = adaptive_recvfrom, // implement
    .getsockopt = NULL,
    .setsockopt = NULL,
    .sendmsg = NULL,
    .recvmsg = NULL,
    .getpeername = NULL,
    .getsockname = NULL,
};

static void adaptive_update_net_if_statuses()
{
    k_mutex_lock(&adapt_sockets_layer.lock, K_FOREVER);
    adapt_sockets_layer.net_if_1_operational = adaptive_net_if_is_operational(adapt_sockets_layer.net_if_1);
    if (!adapt_sockets_layer.net_if_1_operational)
    {
        adapt_sockets_layer.net_if_1_successful_stable_checks = 0;
    }
    adapt_sockets_layer.net_if_2_operational = adaptive_net_if_is_operational(adapt_sockets_layer.net_if_2);
    k_mutex_unlock(&adapt_sockets_layer.lock);
}

static void net_if_status_monitor_thread(void *p1, void *p2, void *p3)
{
    while (true)
    {
        k_sleep(NET_IF_STATUS_POLLING_INTERVAL);
        k_mutex_lock(&adapt_sockets_layer.lock, K_FOREVER);
        adapt_sockets_layer.net_if_1_operational = adaptive_net_if_is_operational(adapt_sockets_layer.net_if_1);
        if (adapt_sockets_layer.net_if_1_operational &&
            adapt_sockets_layer.net_if_1_successful_stable_checks < NET_IF_1_STABLE_CHECKS_NEEDED)
        {
            adapt_sockets_layer.net_if_1_successful_stable_checks++;
        }
        else if (!adapt_sockets_layer.net_if_1_operational)
        {
            adapt_sockets_layer.net_if_1_successful_stable_checks = 0;
        }
        adapt_sockets_layer.net_if_2_operational = adaptive_net_if_is_operational(adapt_sockets_layer.net_if_2);
        k_mutex_unlock(&adapt_sockets_layer.lock);
    }
}

static bool adaptive_net_if_1_is_stable()
{
    return adapt_sockets_layer.net_if_1_successful_stable_checks == NET_IF_1_STABLE_CHECKS_NEEDED;
}

void log_interface_conditions(struct net_if *iface)
{
    if (iface == NULL)
    {
        LOG_ERR("Cannot log conditions: Interface pointer is NULL.");
        return;
    }
    LOG_DBG("Admin up: %d\nCarrier okay: %d\nIs dormant: %d", net_if_is_admin_up(iface), net_if_is_carrier_ok(iface), net_if_is_dormant(iface));
}

void log_ipv4(struct sockaddr *addr, socklen_t addrlen)
{
    if (addr && addrlen >= sizeof(struct sockaddr_in))
    {
        // Assume IPv4 for demonstration (common case)
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        char addr_str[NET_IPV4_ADDR_LEN];

        // Convert the IP address to a human-readable string
        if (net_addr_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str)))
        {

            LOG_DBG("Address: %s:%u",
                    addr_str,
                   ntohs(sin->sin_port));
            LOG_DBG("Address Family (sin_family): %d (AF_INET=2)", sin->sin_family);
        }
        else
        {
            LOG_DBG("Destination Address available, but net_addr_ntop failed.");
        }
    }
    else if (addr)
    {
        LOG_DBG("Destination Address provided, but is NOT IPv4 or size is incorrect. Family: %d",
                addr->sa_family);
    }
    else
    {
        LOG_DBG("Destination Address (addr): NULL");
    }
}

static bool adaptive_net_if_is_operational(struct net_if *iface)
{
    return iface != NULL && net_if_is_admin_up(iface) && net_if_is_carrier_ok(iface) && !net_if_is_dormant(iface);
}

static struct net_if *adaptive_get_prefered_net_if(void)
{
    adaptive_update_net_if_statuses();
    k_mutex_lock(&adapt_sockets_layer.lock, K_FOREVER);
    struct net_if *prefered = NULL;
    if (adapt_sockets_layer.net_if_1_operational && adaptive_net_if_1_is_stable())
    {
        prefered = adapt_sockets_layer.net_if_1;
    }
    else if (adaptive_net_if_is_operational(adapt_sockets_layer.net_if_2))
    {
        prefered = adapt_sockets_layer.net_if_2;
    }
    k_mutex_unlock(&adapt_sockets_layer.lock);
    return prefered;
}

static struct net_if *adaptive_get_inner_net_if(struct device *dev)
{
    if (dev == NULL)
    {
        LOG_ERR("No device given!");
        adapt_sockets_layer.error = ENODEV;
        return -adapt_sockets_layer.error;
    }
    if (!device_is_ready(dev))
    {
        LOG_ERR("Adaptive net device is not ready yet.");
        // Use EBUSY: Resource is busy or not initialized.
        adapt_sockets_layer.error = EBUSY;
        return -adapt_sockets_layer.error;
    }
    struct net_if *iface = net_if_lookup_by_dev(dev);
    if (iface == NULL)
    {
        LOG_ERR("Failed to get network interface for net device!");
        adapt_sockets_layer.error = ENODEV;
        return -adapt_sockets_layer.error;
    }
    return iface;
}

int adaptive_sockets_init(void)
{
    k_mutex_init(&adapt_sockets_layer.lock);
    k_mutex_lock(&adapt_sockets_layer.lock, K_FOREVER);
    adapt_sockets_layer.error = 0;

    // get inner net ifs
    struct device *net_dev_1 = DEVICE_DT_GET(ADAPT_NET_DEV_1);
    adapt_sockets_layer.net_if_1 = adaptive_get_inner_net_if(net_dev_1);
    if (adapt_sockets_layer.net_if_1 == NULL)
    {
        LOG_ERR("Could not find net if for net device 1.");
        adapt_sockets_layer.error = ENODEV;
        return -ENODEV;
    }
    struct device *net_dev_2 = DEVICE_DT_GET(ADAPT_NET_DEV_2);
    adapt_sockets_layer.net_if_2 = adaptive_get_inner_net_if(net_dev_2);
    if (adapt_sockets_layer.net_if_2 == NULL)
    {
        LOG_ERR("Could not find net if for net device 2.");
        adapt_sockets_layer.error = ENODEV;
        return -ENODEV;
    }

    // create a thread to monitor net ifs
    adapt_sockets_layer.monitor_tid = k_thread_create(
        &adapt_sockets_layer.monitor_thread_data,
        monitor_stack_area,
        K_THREAD_STACK_SIZEOF(monitor_stack_area),
        net_if_status_monitor_thread,
        NULL, NULL, NULL,
        NET_IF_STATUS_POLLING_PRIORITY,
        0,
        K_NO_WAIT);

    // set net ifs current status
    adapt_sockets_layer.net_if_1_operational = adaptive_net_if_is_operational(adapt_sockets_layer.net_if_1);
    adapt_sockets_layer.net_if_2_operational = adaptive_net_if_is_operational(adapt_sockets_layer.net_if_2);
    k_mutex_unlock(&adapt_sockets_layer.lock);
    return 0;
}

static int adaptive_connect(void *obj, const struct sockaddr *dest_addr, socklen_t dest_addr_len)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_connect for socket %d...", socket->fd);

    // destination might be given here or in the send function. This is to account for both cases.
    // we're storing destination for later
    socket->dest_addr = dest_addr;
    socket->dest_addr_len = dest_addr_len;
    // we need to be bound at this stage cause net_context_connect might try to call net_offloaded funcs
    struct net_if *iface = adaptive_get_prefered_net_if();
    net_context_bind_iface(socket->context, iface);
    int error = net_context_connect(
        socket->context,
        dest_addr,
        dest_addr_len,
        NULL,
        K_FOREVER,
        NULL);
    if (error < 0)
    {
        LOG_ERR("Failed to connect the net context. Error: %d.", error);
    }
    socket->connected = error == 0;
    return error;
}

void adaptive_on_send(struct net_context *context, int status, void *user_data)
{
    LOG_DBG("Running adaptive_on_send...");
}

static ssize_t adaptive_sendto(void *obj, const void *buf, size_t buf_len, int flags,
                               struct sockaddr *dest_addr, socklen_t dest_addr_len)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_sendto for socket %d...", socket->fd);


    if (socket->send_buf != NULL)
    {
        // in case of socket reuse before callin recv
        k_free(socket->send_buf);
        socket->send_buf = NULL;
        socket->send_buf_len = 0;
    }

    uint8_t try = 0;
    while (try < ADAPTIVE_MAX_SEND_TRIES)
    {
        if (!socket->connected)
        {
            adaptive_connect(socket, dest_addr, dest_addr_len);
        }
        if (!dest_addr == NULL)
        {
            socket->dest_addr = dest_addr;
            socket->dest_addr_len = dest_addr_len;
        }

        if (socket->dest_addr == NULL)
        {
            return -EINVAL;
        }
        int bytes_sent = 0;
        bytes_sent = net_context_sendto(
            socket->context,
            buf,
            buf_len,
            socket->dest_addr,
            socket->dest_addr_len,
            adaptive_on_send,
            K_FOREVER,
            NULL);
        if (bytes_sent >= 0)
        {
            socket->send_buf = k_calloc(buf_len, 1); // free in recv and in close socket
            if (socket->send_buf == NULL)
            {
                socket->send_buf_len = 0;
                // failed to store data
                // send is still a success
                // so that means we should continue with the network operations
                // we just wont be able to retry in recv.
            }
            else
            {
                memcpy(socket->send_buf, buf, buf_len);
                socket->send_buf_len = buf_len;
            }
            return bytes_sent; // SUCCESS EXIT CONDITION
        }
        else if (try == ADAPTIVE_MAX_SEND_TRIES - 1)
        {
            // we wont be trying again
            return bytes_sent; // contains an error code
        }
        // retry logic needs to go here
        // get new preferred net if
        struct net_if *preferred_iface = adaptive_get_prefered_net_if();
        if (preferred_iface == NULL)
        {
            // return an error for net if down
            return ENETDOWN;
        }
        // if got it, retry using that net if
        socket->net_if = preferred_iface;
        socket->connected = false;
        try++;
    }
}

static void adaptive_on_receive
    struct net_context *context,
    struct net_pkt *pkt,
    union net_ip_header *ip_hdr,
    union net_proto_header *proto_hdr,
    int status,
    void *user_data)
{
    LOG_DBG("Running adaptive_on_receive...");
    struct adaptive_socket *socket = (struct adaptive_socket *)user_data;
    socket->recv_pkt = pkt;
    k_sem_give(&socket->recv_pkt_sem);
}

static ssize_t adaptive_recvfrom(void *obj, void *buf, size_t buf_len, int flags,
                                 struct sockaddr *src_addr, socklen_t *src_addr_len)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_recvfrom for socket %d...", socket->fd);
    ssize_t error = 0;
    uint8_t try = 0;
    while (try < ADAPTIVE_MAX_RECV_TRIES)
    {
        error = (ssize_t)net_context_recv(socket->context, adaptive_on_receive, K_FOREVER, socket);
        if (error < 0)
        {
            LOG_ERR("Failed to receive data from context. Error: %d.", error);
            goto retry;
        }
        error = (ssize_t)k_sem_take(&socket->recv_pkt_sem, K_SECONDS(60));
        if (error == -EAGAIN)
        {
            LOG_ERR("Timeout waiting for data.");
            goto retry;
        }

        if (socket->recv_pkt == NULL)
        {
            LOG_ERR("No recieved packet found.");
            goto retry;
        }
        if (error == 0)
        {
            break;
        }
    retry:
        if (socket->send_buf == NULL)
        {
            // retry not possible
            return error;
        }
        if (try == ADAPTIVE_MAX_RECV_TRIES - 1)
        {
            error = adaptive_sendto(socket, socket->send_buf, socket->send_buf_len, 0, NULL, 0);
            if (error < 0)
            {
                // return because send also failed
               goto cleanup;
            }
        }
        try++;
    }
    // check if error
    if (error < 0)
    {
        goto cleanup;
    }

    size_t pkt_len = net_pkt_get_len(socket->recv_pkt);
    // hacky solution: espressif wifi driver seems to add extra 28 bytes of data
    if (net_if_get_wifi_sta() == socket->net_if)
    {
        if (pkt_len < 28)
        {
            error = -EMSGSIZE;
            goto cleanup;
        }
        else
        {
            pkt_len = pkt_len - 28;
        }
    }
    ssize_t bytes_to_copy = (pkt_len < buf_len ? pkt_len : buf_len);
    LOG_DBG("max_length: %zu, packet_length: %zu, bytes_to_copy: %zu", buf_len, pkt_len, bytes_to_copy);
    net_pkt_cursor_init(socket->recv_pkt);
    error = (ssize_t)net_pkt_read(socket->recv_pkt, buf, bytes_to_copy);
    if (error < 0)
    {
        LOG_ERR("Failed to read network packet. Error code: %d.", error);
    }
cleanup:
    if (socket->recv_pkt != NULL)
    {
        net_pkt_unref(socket->recv_pkt); // unref the packet regardless of whether it was read successfully.
        socket->recv_pkt = NULL;
    }
    k_free(socket->send_buf);
    socket->send_buf = NULL;
    socket->send_buf_len = 0;
    return error == 0 ? (ssize_t)bytes_to_copy : error;
}

static int adaptive_close(void *obj)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_close for socket %d...", socket->fd);
    int error = net_context_put(socket->context);
    if (error < 0)
    {
        LOG_ERR("Failed to put network context. Error %d.", error);
    }
    zvfs_free_fd(socket->fd);
    k_free(socket->send_buf);
    socket->send_buf = NULL;
    socket->send_buf_len = 0;
    if (socket->recv_pkt != NULL)
    {
        net_pkt_unref(socket->recv_pkt);
    }
    k_free(socket);
    return 0;
}

static bool adaptive_connection_is_supported(int family, int type, int proto)
{
    LOG_DBG("Running adaptive_connection_is_supported...");
    return family == AF_INET && type == SOCK_DGRAM && proto == IPPROTO_UDP;
}

static int adaptive_get_socket(int family, int type, int proto)
{
    LOG_DBG("Running adaptive_get_socket...");

    // creates a socket
    struct adaptive_socket *socket = k_calloc(1, sizeof(struct adaptive_socket));
    if (socket == NULL)
    {
        return -ENOMEM;
    }

    // gets a file descriptor
    int fd = zvfs_reserve_fd();
    if (fd < 0)
    {
        return fd; // contains an error
    }
    socket->fd = fd;
    zvfs_finalize_typed_fd(
        socket->fd,
        socket,
        (struct fd_op_vtable *)&adapt_socket_ops,
        ZVFS_MODE_IFSOCK);

    // gets a context
    int error_code = net_context_get(family, type, proto, &socket->context);
    if (error_code < 0)
    {
        LOG_ERR("Failed to get a network context. Error %d.", error_code);
    }
    // socket remained unbound
    // bind it as late as possible
    k_sem_init(&socket->recv_pkt_sem, 0, 1);
    return socket->fd;
}

NET_SOCKET_OFFLOAD_REGISTER(
    adaptive_sockets,
    CONFIG_ADAPTIVE_SOCKETS_PRIORITY,
    AF_INET,
    adaptive_connection_is_supported,
    adaptive_get_socket);