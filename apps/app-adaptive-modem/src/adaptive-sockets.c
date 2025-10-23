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

// compile time checks
#if !DT_NODE_HAS_STATUS(ADAPT_NET_DEV_1, okay)
#error "Devicetree alias 'adaptive-net-device-1' is missing or disabled. Please define it in your board overlay."
#endif

void log_interface_conditions(struct net_if *iface)
{
    if (iface == NULL) {
        LOG_ERR("Cannot log conditions: Interface pointer is NULL.");
        return;
    }
    LOG_DBG("Admin up: %d\nCarrier okay: %d\nIs dormant: %d", net_if_is_admin_up(iface), net_if_is_carrier_ok(iface), net_if_is_dormant(iface));
    
}


/*
 * Holds data for and Adaptive Socket
 */
struct adaptive_socket
{
    int fd;
    struct net_context *context;
    struct k_sem recv_pkt_sem;
    struct net_pkt *recv_pkt;
    struct sockaddr *dest_addr;
    socklen_t dest_addr_len;
    int error;
};

/*
 * Holds data for the Adaptive Sockets Layer
 */
struct adaptive_sockets_layer
{
    struct net_if *net_if_1;
    int error;
};

static struct adaptive_sockets_layer adapt_sockets_layer = {0};
static int adaptive_close(void *obj);
static int adaptive_connect(void *obj, const struct sockaddr *dest_addr, socklen_t dest_addr_len);
static ssize_t adaptive_sendto(void *obj, const void *buf, size_t buf_len, int flags, const struct sockaddr *dest_addr, socklen_t dest_addr_len);
static ssize_t adaptive_recvfrom(void *obj, void *buf, size_t buf_len, int flags, struct sockaddr *src_addr, socklen_t *src_addr_len);

static const struct socket_op_vtable adapt_socket_ops = {
    .fd_vtable = {
        .read = NULL,   // implement as caller for recvfrom
        .write = NULL, // implement as caller for sendto
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



int adaptive_sockets_init(void)
{
    if (adapt_sockets_layer.error != 0) {
        LOG_ERR("Cannot initialize adaptive sockets layer while in an error state!");
        return -adapt_sockets_layer.error;
    }
    adapt_sockets_layer.error = 0;
    struct device * net_dev_1 = DEVICE_DT_GET(ADAPT_NET_DEV_1);
    if (net_dev_1 == NULL)
    {
        LOG_ERR("Failed to get net device 1!");
        adapt_sockets_layer.error = ENODEV;
        return -adapt_sockets_layer.error;
    }
    if (!device_is_ready(net_dev_1)) {
        LOG_ERR("Device 'adaptive-net-device-1' is not ready yet.");
        // Use EBUSY: Resource is busy or not initialized.
        adapt_sockets_layer.error = EBUSY;
        return -adapt_sockets_layer.error;
    }
    adapt_sockets_layer.net_if_1 = net_if_lookup_by_dev(net_dev_1);
    if (adapt_sockets_layer.net_if_1 == NULL)
    {
        LOG_ERR("Failed to get network interface for net device 1!");
        adapt_sockets_layer.error = ENODEV;
        return -adapt_sockets_layer.error;
    }
    log_interface_conditions(adapt_sockets_layer.net_if_1);
    // do some more init stuff
    return -adapt_sockets_layer.error;
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
    k_free(socket);
    return 0;
}

static int adaptive_connect(void *obj, const struct sockaddr *dest_addr, socklen_t dest_addr_len)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_connect for socket %d...", socket->fd);
    // LOG_DBG("addrlen: %d", addrlen);
    // log_ipv4(addr, addrlen);
    // LOG_DBG("----------------------------");
    socket->dest_addr = dest_addr;
    socket->dest_addr_len = dest_addr_len;
    net_context_connect(
        socket->context,
        dest_addr,
        dest_addr_len,
        NULL,
        K_FOREVER,
        NULL);
    return 0;
}

void on_send(struct net_context *context, int status, void *user_data)
{
    LOG_DBG("Running on_send...");
}


void on_receive(
    struct net_context *context,
    struct net_pkt *pkt,
    union net_ip_header *ip_hdr,
    union net_proto_header *proto_hdr,
    int status,
    void *user_data)
{
    if (status != 0) {
        return;
    }
    LOG_DBG("Running on_receive...");
    struct adaptive_socket *socket = (struct adaptive_socket *)user_data;
    socket->recv_pkt = pkt;
    k_sem_give(&socket->recv_pkt_sem);
}

static ssize_t adaptive_sendto(void *obj, const void *buf, size_t buf_len, int flags,
                               const struct sockaddr *dest_addr, socklen_t addr_len)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_sendto for socket %d...", socket->fd);
    // LOG_DBG("--- Adaptive Sendto Args ---");
    // LOG_DBG("len: %zu, flags: 0x%x", len, flags);
    // LOG_DBG("addrlen: %d", socket->destination_address_length);
    // log_ipv4(socket->destination_address, addrlen);
    // LOG_DBG("----------------------------");

    // try to send the request over wifi
    return net_context_sendto(
        socket->context,
        buf,
        buf_len,
        socket->dest_addr,
        socket->dest_addr_len,
        on_send,
        K_FOREVER,
        NULL);
}

static ssize_t adaptive_recvfrom(void *obj, void *buf, size_t buf_len, int flags,
                                 struct sockaddr *src_addr, socklen_t *src_addr_len)
{
    int error;
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_recvfrom for socket %d...", socket->fd);
    error = net_context_recv(socket->context, on_receive, K_FOREVER, socket);
    if (error < 0)
    {
        LOG_ERR("Failed to receive data from context. Error: %d.", error);
        return error;
    }
    error = k_sem_take(&socket->recv_pkt_sem, K_SECONDS(60));
    if (error == -EAGAIN)
    {
        LOG_ERR("Timeout waiting for data.");
        return -ETIMEDOUT;
    }

    if (socket->recv_pkt == NULL)
    {
        LOG_ERR("No recieved packet found.");
        return -1;
    }
    // net_pkt_cursor_init(socket->received_packet);
    size_t pkt_len = net_pkt_get_len(socket->recv_pkt);
    size_t bytes_to_copy = (pkt_len < buf_len ? pkt_len : buf_len);// - 28;
    LOG_DBG("max_length: %zu, packet_length: %zu, bytes_to_copy: %zu", buf_len, pkt_len, bytes_to_copy);
    // net_pkt_cursor_init(socket->received_packet);
    error = net_pkt_read(socket->recv_pkt, buf, bytes_to_copy);
    if (error < 0)
    {
        LOG_ERR("Failed to read network packet. Error code: %d.", error);
    }
    net_pkt_unref(socket->recv_pkt); // unref the packet regardless of whether it was read successfully.
    socket->recv_pkt = NULL;
    return error == 0 ? (ssize_t)bytes_to_copy : (ssize_t)error;
}

static bool adaptive_connection_is_supported(int family, int type, int proto)
{
    LOG_DBG("Running adaptive_connection_is_supported...");
    return family == AF_INET && type == SOCK_DGRAM && proto == IPPROTO_UDP;
}

static int adaptive_get_socket(int family, int type, int proto)
{
    LOG_DBG("Running adaptive_get_socket...");

    if (adapt_sockets_layer.net_if_1 == NULL)
    {
        return -ENETDOWN;
    }

    struct adaptive_socket *socket = k_calloc(1, sizeof(struct adaptive_socket));
    if (socket == NULL)
    {
        return -ENOMEM;
    }
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
    
    int error_code = net_context_get(family, type, proto, &socket->context);
    if (error_code < 0)
    {
        LOG_ERR("Failed to get a network context. Error %d.", error_code);
    }
    net_context_bind_iface(socket->context, adapt_sockets_layer.net_if_1);
    k_sem_init(&socket->recv_pkt_sem, 0, 1);
    return socket->fd;
}

NET_SOCKET_OFFLOAD_REGISTER(
    adaptive_sockets,
    CONFIG_ADAPTIVE_SOCKETS_PRIORITY,
    AF_INET,
    adaptive_connection_is_supported,
    adaptive_get_socket);