#include <lwip/udp.h>
#include <lwip/tcp.h>
#include <net.h>
#include <web_console.h>

#include "http_ans.h"
#include "sha1.h"
#include "base64.h"

typedef struct dhcps_msg {
	uint8_t op, htype, hlen, hops;
	uint8_t xid[4];
	uint8_t secs[2];
	uint8_t flags[2];
	uint8_t ciaddr[4];
	uint8_t yiaddr[4];
	uint8_t siaddr[4];
	uint8_t giaddr[4];
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint8_t options[576];
} dhcps_msg;

static int web_console_inited_flag = 0;
static int web_console_started_flag = 0;

static struct udevice *web_console_udev = NULL;
static struct netif *web_console_nif = NULL;

static struct tcp_pcb *web_console_tcp_pcb = NULL;
static char web_console_symbol = '\0';

static int http_ans_sended = 0;

static const char HTTP_RSP[] = "HTTP/1.1 200 OK\r\n"
			       "Content-Length: %d\r\n"
			       "Content-Type: text/html\r\n\r\n";

static const char WS_RSP[] = "HTTP/1.1 101 Switching Protocols\r\n"
			     "Upgrade: websocket\r\n"
			     "Connection: Upgrade\r\n"
			     "Sec-WebSocket-Accept: %s\r\n\r\n";
static const char WS_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
static const char WS_KEY[] = "Sec-WebSocket-Key: ";

static err_t websocket_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
			    err_t err)
{
	if (p == NULL) {
		web_console_started_flag = 0;
		web_console_tcp_pcb = NULL;
		web_console_symbol = '\0';
		return ERR_OK;
	}

	int data_len = p->tot_len;
	char tcp_rec[data_len];
	pbuf_copy_partial(p, (void *)tcp_rec, data_len, 0);
	tcp_recved(tpcb, data_len);

	if (web_console_started_flag == 0) {
		char *sec_websocket_position_start = strstr(tcp_rec, WS_KEY);
		if (sec_websocket_position_start) {
			sec_websocket_position_start += strlen(WS_KEY);
			char *sec_websocket_position_end =
				strstr(sec_websocket_position_start, "\r\n");

			char sec_and_uid_websockeet[100];
			memcpy(sec_and_uid_websockeet,
			       sec_websocket_position_start,
			       sec_websocket_position_end -
				       sec_websocket_position_start);
			sec_and_uid_websockeet[sec_websocket_position_end -
					       sec_websocket_position_start] =
				0;
			strcat(sec_and_uid_websockeet, WS_GUID);

			char result_sha[20];
			SHA1((unsigned char *)result_sha,
			     (unsigned char *)sec_and_uid_websockeet,
			     strlen(sec_and_uid_websockeet));

			char web_socket_base64[100];
			bintob64(web_socket_base64, result_sha, 20);

			char answer_html[1000];
			sprintf(answer_html, WS_RSP, web_socket_base64);

			tcp_write(tpcb, answer_html, strlen(answer_html), 1);
			tcp_output(tpcb);

			web_console_started_flag = 1;
			web_console_tcp_pcb = tpcb;

			printf(CONFIG_SYS_PROMPT);
		}
	} else {
		uint8_t opcode = tcp_rec[0] & 0x0F;
		switch (opcode) {
		case 0x01:
		case 0x02:
			if (data_len > 6) {
				data_len -= 6;

				for (int i = 0; i < data_len; i++)
					tcp_rec[i + 6] ^= tcp_rec[2 + i % 4];

				tcp_rec[6 + data_len] = 0;

				web_console_symbol = tcp_rec[6];
			}
			break;
		case 0x08:
			break;
		}
	}

	pbuf_free(p);
	return ERR_OK;
}

static err_t http_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p,
		       err_t err)
{
	int data_len = p->tot_len;
	char tcp_rec[data_len];
	pbuf_copy_partial(p, (void *)tcp_rec, data_len, 0);
	tcp_recved(tpcb, data_len);
	pbuf_free(p);

	char answer_html[1000];
	sprintf(answer_html, HTTP_RSP, http_ans_len);

	tcp_write(tpcb, answer_html, strlen(answer_html), 0x01);
	tcp_output(tpcb);

	http_ans_sended = 0;

	return ERR_OK;
}

static err_t http_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
	int send_size = 1000;

	if (http_ans_len - http_ans_sended > send_size) {
		tcp_write(tpcb, http_ans + http_ans_sended, send_size, 0x01);
	} else {
		tcp_write(tpcb, http_ans + http_ans_sended,
			  http_ans_len - http_ans_sended, 0x01);
	}
	tcp_output(tpcb);

	http_ans_sended += send_size;

	return ERR_OK;
}

static void dhcp_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
		      const ip_addr_t *addr, u16_t port)
{
	if (p == NULL)
		return;

	dhcps_msg dhcp_rec;

	int data_len = p->tot_len;
	pbuf_copy_partial(p, (void *)&dhcp_rec, data_len, 0);
	pbuf_free(p);

	int i = 4;
	while (dhcp_rec.options[i] != 255 && dhcp_rec.options[i] != 53) {
		i += dhcp_rec.options[i + 1] + 2;
	}

	uint8_t dchp_state;

	if (dhcp_rec.options[i] == 53) {
		dchp_state = dhcp_rec.options[i + 2];
	} else {
		return;
	}

	memset(&dhcp_rec.options, 0, 576);

	dhcp_rec.op = 0x02;

	dhcp_rec.yiaddr[0] = 0xc0;
	dhcp_rec.yiaddr[1] = 0xa8;
	dhcp_rec.yiaddr[2] = 0x0a;
	dhcp_rec.yiaddr[3] = 0x02;

	dhcp_rec.siaddr[0] = 0xc0;
	dhcp_rec.siaddr[1] = 0xa8;
	dhcp_rec.siaddr[2] = 0x0a;
	dhcp_rec.siaddr[3] = 0x01;

	dhcp_rec.options[0] = 99;
	dhcp_rec.options[1] = 130;
	dhcp_rec.options[2] = 83;
	dhcp_rec.options[3] = 99;

	if (dchp_state == 1) {
		dhcp_rec.options[4] = 53;
		dhcp_rec.options[5] = 1;
		dhcp_rec.options[6] = 2;
	}

	if (dchp_state == 3) {
		dhcp_rec.options[4] = 53;
		dhcp_rec.options[5] = 1;
		dhcp_rec.options[6] = 5;
	}

	dhcp_rec.options[7] = 54;
	dhcp_rec.options[8] = 4;
	dhcp_rec.options[9] = 0xc0;
	dhcp_rec.options[10] = 0xa8;
	dhcp_rec.options[11] = 0x0a;
	dhcp_rec.options[12] = 0x01;

	dhcp_rec.options[13] = 1;
	dhcp_rec.options[14] = 4;
	dhcp_rec.options[15] = 0xff;
	dhcp_rec.options[16] = 0xff;
	dhcp_rec.options[17] = 0xff;
	dhcp_rec.options[18] = 0x00;

	dhcp_rec.options[19] = 28;
	dhcp_rec.options[20] = 4;
	dhcp_rec.options[21] = 0xc0;
	dhcp_rec.options[22] = 0xa8;
	dhcp_rec.options[23] = 0x0a;
	dhcp_rec.options[24] = 0xff;

	dhcp_rec.options[25] = 51;
	dhcp_rec.options[26] = 4;
	dhcp_rec.options[27] = 0x00;
	dhcp_rec.options[28] = 0x01;
	dhcp_rec.options[29] = 0x51;
	dhcp_rec.options[30] = 0x80;

	dhcp_rec.options[31] = 255;

	p = pbuf_alloc(PBUF_TRANSPORT, data_len, PBUF_RAM);
	memcpy(p->payload, &dhcp_rec, data_len);

	udp_sendto(pcb, p, IP_ADDR_BROADCAST, 68);

	pbuf_free(p);
}

static err_t websocket_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	LWIP_UNUSED_ARG(arg);
	LWIP_UNUSED_ARG(err);

	if (!web_console_started_flag) {
		tcp_recv(newpcb, websocket_recv);
		return ERR_OK;
	} else {
		tcp_abort(newpcb);
		return ERR_ABRT;
	}
}

static err_t http_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	LWIP_UNUSED_ARG(arg);
	LWIP_UNUSED_ARG(err);

	if (!web_console_started_flag) {
		tcp_recv(newpcb, http_recv);
		tcp_sent(newpcb, http_sent);
		return ERR_OK;
	} else {
		tcp_abort(newpcb);
		return ERR_ABRT;
	}
}

void web_console_init(void)
{
	if (net_lwip_eth_start() < 0) {
		return;
	}

	web_console_udev = eth_get_dev();

	web_console_nif = net_lwip_new_netif_noip(web_console_udev);
	if (!web_console_nif) {
		return;
	}

	ip4_addr_t ip, mask, gw;
	IP4_ADDR(&ip, 192, 168, 10, 1);
	IP4_ADDR(&mask, 255, 255, 255, 0);
	IP4_ADDR(&gw, 192, 168, 10, 2);
	netif_set_addr(web_console_nif, &ip, &mask, &gw);

	struct tcp_pcb *websocket = tcp_new();
	tcp_bind(websocket, IP_ADDR_ANY, 3000);
	websocket =
		tcp_listen_with_backlog(websocket, TCP_DEFAULT_LISTEN_BACKLOG);
	tcp_accept(websocket, websocket_accept);

	struct tcp_pcb *http = tcp_new();
	tcp_bind(http, IP_ADDR_ANY, 80);
	http = tcp_listen_with_backlog(http, TCP_DEFAULT_LISTEN_BACKLOG);
	tcp_accept(http, http_accept);

	struct udp_pcb *dhcp = udp_new();
	udp_bind(dhcp, IP_ADDR_ANY, 67);
	udp_recv(dhcp, dhcp_recv, NULL);

	web_console_started_flag = 0;
	web_console_tcp_pcb = NULL;
	web_console_symbol = '\0';

	web_console_inited_flag = 1;
}

int web_console_inited(void)
{
	return web_console_inited_flag;
}

int web_console_started(void)
{
	return web_console_started_flag;
}

char web_console_getc(void)
{
	net_lwip_rx(web_console_udev, web_console_nif);
	char symbol = web_console_symbol;
	web_console_symbol = '\0';

	return symbol;
}

void web_console_putc(const char c)
{
	unsigned char buf[3];
	buf[0] = 0x80 | 0x01;
	buf[1] = 1;
	buf[2] = c;
	tcp_write(web_console_tcp_pcb, buf, 3, 1);
	tcp_output(web_console_tcp_pcb);
}

void web_console_puts(const char *s)
{
	int len = strlen(s);
	unsigned char buf[150];
	while (len) {
		int send_len = min(len, 125);
		buf[0] = 0x80 | 0x01;
		buf[1] = send_len;
		memcpy(&buf[2], s, send_len);
		tcp_write(web_console_tcp_pcb, buf, send_len + 2, 1);
		len -= send_len;
		s += send_len;
	}
	tcp_output(web_console_tcp_pcb);
}
