#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(adaptive_sockets, LOG_LEVEL_DBG);
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/net_pkt.h>
// #include <zephyr/net/net_core.h>
// #include <zephyr/net/net_ip.h>

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

// void log_netif_ip_address(struct net_if *iface)
// {
//     if (!iface) {
//         LOG_ERR("Cannot log IP: Interface pointer is NULL.");
//         return;
//     }

//     // Allocate a buffer to hold the human-readable IP address string
//     char ip_addr_str[NET_IPV4_ADDR_LEN] = {0};

//     // 1. Get the first valid IPv4 address structure
//     struct net_if_addr *if_addr = net_if_ipv4_get_addr(iface, NET_ADDR_ANY, NET_ADDR_VALID);

//     if (if_addr) {
//         // 2. Convert the binary IP address data to a string
//         net_addr_ntop(AF_INET, &if_addr->address.in_addr, ip_addr_str, sizeof(ip_addr_str));

//         // 3. Log the result
//         LOG_INF("Interface %p successfully acquired IP: %s", iface, ip_addr_str);
//     } else {
//         // 4. Handle failure case
//         LOG_WRN("Interface %p has NO valid IPv4 address yet (Still 0.0.0.0).", iface);
//     }
// }

/*
 * Holds data for and Adaptive Socket
 */
struct adaptive_socket
{
    int fd;
    struct net_context *wifi_context;
    struct k_sem receive_packet_semaphore;
    struct net_pkt *received_packet;
    struct sockaddr *destination_address;
    socklen_t destination_address_length;
    int error;
};

/*
 * Holds data for the Adaptive Sockets Layer
 */
struct adaptive_sockets_layer
{
    struct net_if *wifi_iface;
    int error;
};

static struct adaptive_sockets_layer adapt_sockets_layer;

static ssize_t adaptive_read(void *obj, void *buf, size_t sz);
static ssize_t adaptive_write(void *obj, const void *buf, size_t sz);
static int adaptive_close(void *obj);
static int adaptive_connect(void *obj, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t adaptive_sendto(void *obj, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
static ssize_t adaptive_recvfrom(void *obj, void *buf, size_t max_len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

static const struct socket_op_vtable adaptive_socket_ops = {
    .fd_vtable = {
        .read = adaptive_read,   // implement as caller for recvfrom
        .write = adaptive_write, // implement as caller for sendto
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

static void adaptive_set_wifi_iface_if_wifi_iface(struct net_if *iface, void *user_data)
{
    if (adapt_sockets_layer.wifi_iface == NULL && net_if_is_wifi(iface))
    {
        adapt_sockets_layer.wifi_iface = iface;
    }
}

int adaptive_sockets_init()
{
    adapt_sockets_layer.error = 0;
    adapt_sockets_layer.wifi_iface = net_if_get_wifi_sta();
    if (adapt_sockets_layer.error != 0)
    {
        LOG_ERR("Failed to get wifi station network interface!");
        return -adapt_sockets_layer.error;
    }
    // do some more init stuff
    return -adapt_sockets_layer.error;
}

static ssize_t adaptive_read(void *obj, void *buf, size_t sz)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_read for socket %d...", socket->fd);
    return sz > 0 ? 10 : 0;
}

static ssize_t adaptive_write(void *obj, const void *buf, size_t sz)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_write for socket %d...", socket->fd);
    return sz;
}

static int adaptive_close(void *obj)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_close for socket %d...", socket->fd);
    int error_code = net_context_put(socket->wifi_context);
    if (error_code < 0)
    {
        LOG_ERR("Failed to put network context. Error %d.", error_code);
    }
    k_free(socket);
    return 0;
}

static int adaptive_connect(void *obj, const struct sockaddr *addr, socklen_t addrlen)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_connect for socket %d...", socket->fd);
    LOG_DBG("addrlen: %d", addrlen);
    log_ipv4(addr, addrlen);
    // LOG_DBG("----------------------------");
    socket->destination_address = addr;
    socket->destination_address_length = addrlen;
    net_context_connect(socket->wifi_context, addr, addrlen, NULL, K_FOREVER, NULL);
    return 0;
}

void on_send_by_wifi(struct net_context *context, int status, void *user_data)
{
    LOG_DBG("Sent");
}

void on_receieve_by_wifi(
    struct net_context *context,
    struct net_pkt *packet,
    union net_ip_header *ip_hdr,
    union net_proto_header *proto_hdr,
    int status, void *user_data)
{

    LOG_DBG("Recieved");
    struct adaptive_socket *socket = (struct adaptive_socket *)user_data;
    socket->received_packet = packet;
    k_sem_give(&socket->receive_packet_semaphore);
}

static ssize_t adaptive_sendto(void *obj, const void *buf, size_t len, int flags,
                               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    struct adaptive_socket *socket = (struct adaptive_socket *)obj;
    LOG_DBG("Running adaptive_sendto for socket %d...", socket->fd);
    // LOG_DBG("--- Adaptive Sendto Args ---");
    // LOG_DBG("len: %zu, flags: 0x%x", len, flags);
    // LOG_DBG("addrlen: %d", socket->destination_address_length);
    // log_ipv4(socket->destination_address, addrlen);
    // LOG_DBG("----------------------------");

    // try to send the request over wifi
    return net_context_sendto(socket->wifi_context, buf, len, socket->destination_address, socket->destination_address_length, on_send_by_wifi, K_FOREVER, NULL);
}

static ssize_t adaptive_recvfrom(void *object, void *buffer, size_t max_length, int flags,
                                 struct sockaddr *source_address, socklen_t *address_length)
{
    int error_code;
    struct adaptive_socket *socket = (struct adaptive_socket *)object;
    LOG_DBG("Running adaptive_recvfrom for socket %d...", socket->fd);
    error_code = net_context_recv(socket->wifi_context, on_receieve_by_wifi, K_FOREVER, socket);
    if (error_code < 0)
    {
        LOG_ERR("Failed to receive data from wifi context. Error: %d.", error_code);
        return error_code;
    }
    error_code = k_sem_take(&socket->receive_packet_semaphore, K_SECONDS(60));
    if (error_code == -EAGAIN)
    {
        LOG_ERR("Timeout waiting for data.");
        return -ETIMEDOUT;
    }

    if (socket->received_packet == NULL)
    {
        LOG_ERR("No recieved packet found.");
        return -1;
    }
    size_t packet_length = net_pkt_get_len(socket->received_packet);
    size_t bytes_to_copy = packet_length < max_length ? packet_length : max_length;
    LOG_DBG("max_length: %zu, packet_length: %zu, bytes_to_copy: %zu", max_length, packet_length, bytes_to_copy);
    error_code = net_pkt_read(socket->received_packet, buffer, bytes_to_copy);
    if (error_code < 0)
    {
        LOG_ERR("Failed to read network packet. Error code: %d.", error_code);
    }
    net_pkt_unref(socket->received_packet); // unref the packet regardless of whether it was read successfully.
    socket->received_packet = NULL;
    return error_code == 0 ? (ssize_t)bytes_to_copy : (ssize_t)error_code;
}

static bool adaptive_connection_is_supported(int family, int type, int proto)
{
    LOG_DBG("Running adaptive_connection_is_supported...");
    return family == AF_INET && type == SOCK_DGRAM && proto == IPPROTO_UDP;
}

static int adaptive_get_socket(int family, int type, int proto)
{
    LOG_DBG("Running adaptive_get_socket...");
    struct adaptive_socket *socket = k_calloc(1, sizeof(struct adaptive_socket));
    if (socket == NULL)
    {
        return -ENOMEM;
    }
    int fd = zvfs_reserve_fd();
    if (fd < 0)
    {
        k_free(socket);
        return fd; // contains an error
    }
    socket->fd = fd;
    zvfs_finalize_typed_fd(
        socket->fd,
        socket,
        (struct fd_op_vtable *)&adaptive_socket_ops,
        ZVFS_MODE_IFSOCK);
    if (adapt_sockets_layer.wifi_iface == NULL)
    {
        k_free(socket);
        return -ENETDOWN;
    }
    int error_code = net_context_get(family, type, proto, &socket->wifi_context);
    if (error_code < 0)
    {
        LOG_ERR("Failed to get a network context. Error %d.", error_code);
    }
    // net_context_bind_iface(socket->wifi_context, adapt_sockets_layer.wifi_iface);
    k_sem_init(&socket->receive_packet_semaphore, 0, 1);
    return socket->fd;
}

NET_SOCKET_OFFLOAD_REGISTER(
    adaptive_sockets,
    CONFIG_ADAPTIVE_SOCKETS_PRIORITY,
    AF_INET,
    adaptive_connection_is_supported,
    adaptive_get_socket);