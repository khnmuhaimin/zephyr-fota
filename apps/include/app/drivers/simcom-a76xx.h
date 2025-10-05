#ifndef EEE4022S_A76XX_H
#define EEE4022S_A76XX_H

#include <stdint.h>

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/net/socket_offload.h>

#include <modem_context.h>
#include <modem_cmd_handler.h>
#include <modem_iface_uart.h>
#include <modem_socket.h>

#define A76XX_MAX_DATA_LENGTH 1024
#define A76XX_RECEIVE_BUFFER_SIZE 1024
#define A76XX_MAX_SOCKETS 5

struct a76xx_data_t
{
    /*
	 * Network interface of the sim module.
	 */
	struct net_if *netif;
	uint8_t mac_addr[6];
	/*
	 * Uart interface of the modem.
	 */
	struct modem_iface_uart_data iface_data;
	uint8_t iface_rb_buf[A76XX_MAX_DATA_LENGTH];
	/*
	 * Modem command handler.
	 */
	struct modem_cmd_handler_data cmd_handler_data;
	uint8_t cmd_match_buf[A76XX_RECEIVE_BUFFER_SIZE + 1];
	/*
	 * Modem socket data.
	 */
	struct modem_socket_config socket_config;
	struct modem_socket sockets[A76XX_MAX_SOCKETS];
};

#endif