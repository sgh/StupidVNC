/*
 * StupidVNC
 *
 * This library is free software; you can redistribute it and/o
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "stupidvnc.h"
#include "ws.h"

#include <zlib.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/provider.h>

#ifndef _WIN32
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <netdb.h>
	#include <netinet/tcp.h>
	#include <arpa/inet.h>
#else
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
	#undef WIN32_LEAN_AND_MEAN
	typedef int socklen_t;
#endif

#include <string>
#include <thread>
#include <list>
#include <vector>
#include <algorithm>
#include <chrono>
#include <mutex>

#define GNU_SOURCE
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <cinttypes>
#include <cstdint>
#include <cassert>

static constexpr int ZOUT_INCREMENT = 4096;

#define ZRLE_SUB_ENCODING_RAW 0
#define ZRLE_SUB_ENCODING_SOLIDCOLOR 1
#define ZRLE_SUB_ENCODING_PLAIN_RLE 128

// +--------+-----------------------------+
// | Number | Name                        |
// +--------+-----------------------------+
// | 0      | Raw                         |
// | 1      | CopyRect                    |
// | 2      | RRE                         |
// | 5      | Hextile                     |
// | 15     | TRLE                        |
// | 16     | ZRLE                        |
// | -239   | Cursor pseudo-encoding      |
// | -223   | DesktopSize pseudo-encoding |
// +--------+-----------------------------+
#define RFB_ENCODING_RAW 0
#define RFB_ENCODING_COPYRECT 1
#define RFB_ENCODING_RRE 2
#define RFB_ENCODING_HEXTILE 5
#define RFB_ENCODING_TRLE 15
#define RFB_ENCODING_ZRLE 16
#define RFB_ENCODING_CURSOR_PSEUDO -239
#define RFB_ENCODING_DESKTOPSIZE_PSEUDO -223

// https://www.wikiwand.com/en/RFB_protocol
// https://github.com/novnc/noVNC/blob/master/core/encodings.js
// https://vncdotool.readthedocs.io/en/0.8.0/rfbproto.html
// https://liu.diva-portal.org/smash/get/diva2:1823614/FULLTEXT02.pdf

// encoding UNKNOWN (7)       // Tight
// encoding ZRLE
// encoding UNKNOWN (21)       // JPEG
// encoding HEXTILE
// encoding RRE
// encoding RAW
// encoding UNKNOWN (-26)
// encoding DESKTOP
// encoding UNKNOWN  -256 -- -247   CompressLevel (Tight encoding)
// encoding UNKNOWN (-224) // LastRect
// encoding UNKNOWN (-258) // QEMU Extended keyboard
// encoding UNKNOWN (-260) // TightPNG
// encoding UNKNOWN (-261) // QEMYLedEvent
// encoding UNKNOWN (-307) // DesktopName
// encoding UNKNOWN (-308) // ExtendedDesktopSize
// encoding UNKNOWN (-309) // Xvp
// encoding UNKNOWN (-312) // Fence
// encoding UNKNOWN (-313) // ContinuousUpdates
// encoding UNKNOWN (-1063131698)  // ExtendedClipboard
// encoding UNKNOWN (1464686180)   // VMwareCursor

#define RFB_SEC_INVALID 0
#define RFB_SEC_NONE    1
#define RFB_SEC_VNC     2

#define RFB_STATUS_OK 0
#define RFB_STATUS_FAILED 1

static constexpr bool TRACE_INFO = true;
static constexpr bool TRACE_DIRTY = false;
static constexpr bool TRACE_DEBUG = false;
static constexpr bool TRACE_COMM = false;
static constexpr bool TRACE_CONNECITONS = true;
static constexpr bool TRACE_MSG = false;

enum ClientToServerMsg {
	RFB_SET_PIXEL_FORMAT      = 0,
	RFB_SET_ENCODINGS         = 2,
	RFB_FRAME_UPDATE_REQUEST  = 3,
	RFB_KEY_EVENT             = 4,
	RFB_POINTER_EVENT         = 5,
	RFB_CLIENT_CUT_TEXT       = 6,
};

enum Server2ClientMsg {
	RFB_FRAMEBUFFER_UPDATE = 0,
};

struct pixel_format_t {
	uint8_t bpp = 32; // 8+8+8=24 .... why does TigerVNC only accept 32
	uint8_t depth = 24;
	uint8_t big_endian = 0;
	uint8_t truecolor = 1;
	uint16_t red_max = htons(255);
	uint16_t green_max = htons(255);
	uint16_t blue_max = htons(255);
	uint8_t red_shift = 16;
	uint8_t green_shift = 8;
	uint8_t blue_shift = 0;
	uint8_t padding[3];
} __attribute__((packed));
static_assert(sizeof(struct pixel_format_t) == 16, "Wrong pizel_format_t size");

struct RGB {
	uint32_t val:24;
} __attribute__((packed));
static_assert(sizeof(struct RGB) == 3, "Wrong size");

struct zlre_tile_raw {
	uint8_t subencoding = ZRLE_SUB_ENCODING_RAW;
	RGB rgb[64*64];
} __attribute__((packed));
static_assert(sizeof(struct zlre_tile_raw) == 64*64*3+1, "Wrong size");

// +--------------+--------------+--------------+
// | No. of bytes | Type [Value] | Description  |
// +--------------+--------------+--------------+
// | 1            | U8 [3]       | message-type |
// | 1            | U8           | incremental  |
// | 2            | U16          | x-position   |
// | 2            | U16          | y-position   |
// | 2            | U16          | width        |
// | 2            | U16          | height       |
// +--------------+--------------+--------------+
struct frame_update_request_t {
//	uint8_t type;
	uint8_t incremental;
	uint16_t x;
	uint16_t y;
	uint16_t w;
	uint16_t h;
} __attribute__((packed));

// +--------------+--------------+--------------+
// | No. of bytes | Type [Value] | Description  |
// +--------------+--------------+--------------+
// | 1            | U8 [5]       | message-type |
// | 1            | U8           | button-mask  |
// | 2            | U16          | x-position   |
// | 2            | U16          | y-position   |
// +--------------+--------------+--------------+
struct pointer_event_t {
	//	uint8_t type;
	uint8_t button_mask;
	uint16_t x;
	uint16_t y;
} __attribute__((packed));



// +--------------+--------------+------------------------------+
// | No. of bytes | Type [Value] | Description                  |
// +--------------+--------------+------------------------------+
// | 2            | U16          | framebuffer-width in pixels  |
// | 2            | U16          | framebuffer-height in pixels |
// | 16           | PIXEL_FORMAT | server-pixel-format          |
// | 4            | U32          | name-length                  |
// | name-length  | U8 array     | name-string                  |
// +--------------+--------------+------------------------------+
struct server_init_msg_t {
	uint16_t width = 0;
	uint16_t height = 0;
	struct pixel_format_t pixel_format;
	uint32_t namelength = 0;
	char name[0];
} __attribute__((packed));
static_assert(sizeof(struct server_init_msg_t) == 24, "Wrong server_init_msg_t size");

// +--------------+--------------+--------------+
// | No. of bytes | Type [Value] | Description  |
// +--------------+--------------+--------------+
// | 1            | U8 [4]       | message-type |
// | 1            | U8           | down-flag    |
// | 2            |              | padding      |
// | 4            | U32          | key          |
// +--------------+--------------+--------------+
struct key_event_t {
	//	uint8_t type;
	uint8_t down_flag;
	uint16_t padding;
	uint32_t key;
} __attribute__((packed));

// +-----------------+--------------------+
// | Key name        | Keysym value (hex) |
// +-----------------+--------------------+
// | BackSpace       | 0xff08             |
// | Tab             | 0xff09             |
// | Return or Enter | 0xff0d             |
// | Escape          | 0xff1b             |
// | Insert          | 0xff63             |
// | Delete          | 0xffff             |
// | Home            | 0xff50             |
// | End             | 0xff57             |
// | Page Up         | 0xff55             |
// | Page Down       | 0xff56             |
// | Left            | 0xff51             |
// | Up              | 0xff52             |
// | Right           | 0xff53             |
// | Down            | 0xff54             |
// | F1              | 0xffbe             |
// | F2              | 0xffbf             |
// | F3              | 0xffc0             |
// | F4              | 0xffc1             |
// | ...             | ...                |
// | F12             | 0xffc9             |
// | Shift (left)    | 0xffe1             |
// | Shift (right)   | 0xffe2             |
// | Control (left)  | 0xffe3             |
// | Control (right) | 0xffe4             |
// | Meta (left)     | 0xffe7             |
// | Meta (right)    | 0xffe8             |
// | Alt (left)      | 0xffe9             |
// | Alt (right)     | 0xffea             |
// +-----------------+--------------------+

// +--------------+--------------+---------------+
// | No. of bytes | Type [Value] | Description   |
// +--------------+--------------+---------------+
// | 2            | U16          | x-position    |
// | 2            | U16          | y-position    |
// | 2            | U16          | width         |
// | 2            | U16          | height        |
// | 4            | S32          | encoding-type |
// +--------------+--------------+---------------+
struct frame_update_rect_header_t {
	uint16_t x;
	uint16_t y;
	uint16_t w;
	uint16_t h;
	int32_t encoding_type;
} __attribute__((packed));

struct StupidvncServerPrivate {
	uint32_t* framebuffer = nullptr;
	unsigned int fb_width = 0;
	unsigned int fb_height = 0;
	StupidvncCallbacks* cb = nullptr;

	std::mutex server_mutex;
	std::thread thread;
	bool quit = false;

	std::list<StupidClient*> allClients;

	bool fb_geometry_changed = true;
};

// +--------------+--------------+----------------------+
// | No. of bytes | Type [Value] | Description          |
// +--------------+--------------+----------------------+
// | 1            | U8 [0]       | message-type         |
// | 1            |              | padding              |
// | 2            | U16          | number-of-rectangles |
// +--------------+--------------+----------------------+
struct frame_update_header_t {
	uint8_t type;
	uint8_t padding = 0;
	uint16_t num_rects;
} __attribute__((packed));

struct DirtyRect {
	int x;
	int y;
	unsigned int width;
	unsigned int height;
};

struct StupidClient {
	StupidClient(IStupidIO* io) {
		this->io = io;
		int ret = deflateInit(&stream,  Z_DEFAULT_COMPRESSION);
		if (ret != Z_OK) {
			STUPID_LOGE("Error inititializing zstream");
		}
	}
	~StupidClient() {
		deflateEnd(&stream);
		delete io;
	}

	z_stream stream = {};
	pixel_format_t pixel_format;
	bool wants_framebuffer = false;
	bool supports_zrle = false;
	bool supports_fb_geometry_change = false;
	IStupidIO* io;
	unsigned int zout_size = 4096;
	unsigned char* zout = (unsigned char*)realloc(nullptr, zout_size);

	StupidvncServer* server;

	// Challenge used during VNC auth
	unsigned char challenge[16];
	unsigned char response[16];

	std::mutex mutex;
	std::vector<DirtyRect> dirtyRects;
	bool disconnect = false;
	int rand_r;
	int rand_g;
	int rand_b;
};

#ifndef _WIN32
int closesocket(int fd) {
	return ::close(fd);

}
#endif

struct RAWIO : IStupidIO {
	RAWIO(int socket) {
		_socket = socket;
	}

	~RAWIO() {
		close();
	}

	void close() override {
		if (_socket != -1)
			closesocket(_socket);
		_socket = -1;
	}

	int read(void* dst, unsigned int len, bool block) override {
		int ret;
		if (block) {
			ret = ::recv(_socket, (char*)dst, len, 0);
			STUPID_LOG(TRACE_COMM, "recv ret:%d", ret);
			return ret;
		}

		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(_socket, &read_fds);

		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 1000;
		ret = select(_socket+1, &read_fds, nullptr, nullptr, &tv);
		if (ret == 1) {
			ret = ::recv(_socket, (char*)dst, len, 0);
			STUPID_LOG(TRACE_COMM, "recv ret:%d", ret);
			return ret;
		}
		return -1;
	}

	void write(const void* src, unsigned int len) override {
		int ret = send(_socket, (const char*)src, len, 0);
		STUPID_LOG(TRACE_COMM, "send ret:%d", ret);
	}

private:
	int _socket;
};


static bool resolve_hostname(struct sockaddr_in* serveraddr, const char* hostname) {
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *h;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // use AF_INET6 to force IPv6
	hints.ai_socktype = SOCK_STREAM;

	if ( (rv = getaddrinfo( hostname , nullptr , &hints , &servinfo)) != 0) {
		STUPID_LOGE("getaddrinfo: %s\n", gai_strerror(rv));
		return false;
	}

	bool retval = false;
	for(p = servinfo; p != NULL; p = p->ai_next) {
		h = (struct sockaddr_in *) p->ai_addr;
		char ip[32];
		strcpy(ip , inet_ntoa( h->sin_addr ) );
		memcpy(serveraddr, h, sizeof(*h));
		retval = true;
	}

	freeaddrinfo(servinfo); // all done with this structure
	return retval;
}

int bind_server_socket(int port) {
	int sd, rc;
	struct sockaddr_in serveraddr;
	int serveraddrlen = sizeof(serveraddr);

	sd = socket(AF_INET, SOCK_STREAM, 0);
	assert(sd != -1);


	int so_reuseaddr = 1;
	if (setsockopt(sd,SOL_SOCKET, SO_REUSEADDR, (const char*)&so_reuseaddr, sizeof(so_reuseaddr)) < 0) {
		STUPID_LOGE("TCP server - setsockopt() error");
		closesocket(sd);
		return -1;
	}

	resolve_hostname(&serveraddr, "0.0.0.0");
	serveraddr.sin_port = htons(port);
	if ((rc = bind(sd, (struct sockaddr *)&serveraddr, serveraddrlen)) < 0) {
		STUPID_LOGE("Error binding %s", strerror(rc));
		closesocket(sd);
		sd = -1;
	}

	STUPID_LOG(TRACE_INFO, "TCP server - Listening...");
	if (listen(sd, 100) < 0) { // backlog 100
		STUPID_LOGE("TCP server - listen() error");
		closesocket(sd);
		return -1;
	}
	return sd;
}

static void key_event(StupidClient* client) {
	key_event_t msg;
	client->io->read(&msg, sizeof(msg));
	msg.key = ntohl(msg.key);
	STUPID_LOG(TRACE_MSG, "keyevent:  down:%d   key:%u", msg.down_flag, msg.key);
	client->server->_p->cb->keyEvent(client, msg.key, msg.down_flag);
}

void tx_frameupdate_raw(StupidClient* client, int x, int y, unsigned int width, unsigned int height) {
	auto priv = client->server->_p;
	const auto red_shift = client->pixel_format.red_shift;
	const auto green_shift = client->pixel_format.green_shift;
	const auto blue_shift = client->pixel_format.blue_shift;

	int rand_r = client->rand_r;
	int rand_g = client->rand_g;
	int rand_b = client->rand_b;
	const auto show_updated_tiles = client->server->show_updated_tiles;

	for (auto idx=0u; idx < height; idx++) {
		auto srcptr = &priv->framebuffer[priv->fb_width * (y + idx) + x];
		for (auto i=0u; i<width; i++) {
			const auto pix = srcptr[i];
			auto r = (pix >> 0) & 0xff;
			auto g = (pix >> 8) & 0xff;
			auto b = (pix >> 16) & 0xff;
			if (show_updated_tiles) {
				r = r*0.8 + rand_r*0.2;
				g = g*0.8 + rand_g*0.2;
				b = b*0.8 + rand_b*0.2;
			}
			uint32_t val = r << red_shift | g << green_shift | b << blue_shift;
			client->io->write(&val, 4);
		}
	}
}

void run_deflate(StupidClient* client, int flush_mode) {
	auto & stream = client->stream;
	int ret = deflate(&client->stream, flush_mode);
	if (ret != Z_OK) {
		exit(1);
	}
	while (stream.avail_in != 0 || stream.avail_out == 0) {
		if (stream.avail_out == 0) {
			auto old_zout_size = client->zout_size;
			client->zout_size += ZOUT_INCREMENT;
			client->zout = (unsigned char*)realloc(client->zout, client->zout_size);
			stream.next_out = client->zout + old_zout_size;
			stream.avail_out = ZOUT_INCREMENT;
		}

		int ret = deflate(&stream, flush_mode);
		if (ret != Z_OK) {
			exit(1);
		}
	};

	assert(stream.avail_in == 0);
}

int64_t now() {
	auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
	return  std::chrono::duration_cast<std::chrono::microseconds>(since_epoch).count();
}

static void tx_frameupdate_zrle(StupidClient* client, int x, int y, unsigned int width, unsigned int height) {
	auto time_start = now();

	client->stream.avail_out = client->zout_size;
	client->stream.next_out = client->zout;
	client->stream.total_out = 0;
	client->stream.total_in = 0;

	zlre_tile_raw raw;
	auto priv = client->server->_p;

	// CPIXEL is a layout thing *NOT* a values this
	// BGRx -> CPIXEL 3 bytes
	// RxGB -> CPIXEL 4 bytes

	int rand_r = client->rand_r;
	int rand_g = client->rand_g;
	int rand_b = client->rand_b;

	const auto red_shift = client->pixel_format.red_shift;
	const auto green_shift = client->pixel_format.green_shift;
	const auto blue_shift = client->pixel_format.blue_shift;

	const unsigned int tile_size = 64;
    const unsigned int pixel_stride = 3; // 3 bytes per pixel

	const auto show_updated_tiles = client->server->show_updated_tiles;

	// if (show_updated_tiles) { // Per rect update coloring
		// rand_r = rand() & 0xff;
		// rand_g = rand() & 0xff;
		// rand_b = rand() & 0xff;
	// }

	for (auto starty=0u; starty < height; starty += tile_size) {
		unsigned int copy_height = std::min(height - starty, tile_size);

		for (auto startx=0u; startx < width; startx += tile_size) {
			unsigned int copy_width = std::min(width - startx, tile_size);
			auto srcptr = &priv->framebuffer[(x+startx) + (y+starty)*priv->fb_width];
			auto dstptr = raw.rgb;
			for (auto trow=0u; trow<copy_height; trow++) {
				for (auto i=0u; i<copy_width; i++) {
					const auto pix = srcptr[i];
					auto r = (pix >> 0) & 0xff;
					auto g = (pix >> 8) & 0xff;
					auto b = (pix >> 16) & 0xff;
					if (show_updated_tiles) {
						r = r*0.8 + rand_r*0.2;
						g = g*0.8 + rand_g*0.2;
						b = b*0.8 + rand_b*0.2;
					}

					unsigned int val = r << red_shift | g << green_shift | b << blue_shift;
					dstptr->val = val;
					dstptr++;
				}
				srcptr += priv->fb_width;
			}

			client->stream.avail_in = 1 + copy_width * copy_height * pixel_stride;
			client->stream.next_in = (unsigned char*)&raw;
			run_deflate(client, Z_NO_FLUSH);
			assert(client->stream.avail_in == 0);
		}
	}

	assert(client->stream.avail_in == 0);
	assert(client->stream.avail_out > 0);

	run_deflate(client, Z_SYNC_FLUSH);

	assert(client->stream.avail_out > 0);
	assert(client->stream.avail_in == 0);

	auto duration = (now() - time_start) / 1000;
	STUPID_LOG(TRACE_DEBUG, "Write zlib data %lu compressed bytes : %lu raw   time:%" PRIi64 "ms\n", client->stream.total_out, client->stream.total_in, duration);
	uint32_t zlibsize = htonl(client->stream.total_out);
	client->io->write(&zlibsize, sizeof(zlibsize));
	client->io->write(client->zout, client->stream.total_out);
}

void frame_update_request(StupidClient* client) {
	frame_update_request_t msg;
	client->io->read(&msg, sizeof(msg));
	msg.x = ntohs(msg.x);
	msg.y = ntohs(msg.y);
	msg.w = ntohs(msg.w);
	msg.h = ntohs(msg.h);
	STUPID_LOG(TRACE_DEBUG, "Frame update request x:%d y:%d w:%d h:%d \n", msg.x, msg.y, msg.w, msg.h);
	client->wants_framebuffer = true;
}

void framebuffer_update(StupidClient* client) {
	auto priv = client->server->_p;
	priv->cb->framebufferUpdate(client);

	if (client->pixel_format.depth !=24 || client->pixel_format.bpp !=32)
		return;

	client->mutex.lock();
	auto dirtyRects = client->dirtyRects;
	client->dirtyRects.clear();
	client->mutex.unlock();

	if (dirtyRects.empty())
		return;

	STUPID_LOG(TRACE_MSG, "Frame update tx");

	client->wants_framebuffer = false;

	const auto show_updated_tiles = client->server->show_updated_tiles;

	if (show_updated_tiles) { // Per update coloring
		client->rand_r = rand() & 0xff;
		client->rand_g = rand() & 0xff;
		client->rand_b = rand() & 0xff;
	}

	frame_update_header_t msg2;
	msg2.type = RFB_FRAMEBUFFER_UPDATE;
	msg2.num_rects = htons(dirtyRects.size());
	client->io->write(&msg2, sizeof(msg2));

	for (auto & rect : dirtyRects) {
		STUPID_LOG(TRACE_DEBUG, "Update %d %d %d %d", rect.x, rect.y, rect.width, rect.height);

		frame_update_rect_header_t msg3;
		msg3.x = htons(rect.x);
		msg3.y = htons(rect.y);
		msg3.w = htons(rect.width);
		msg3.h = htons(rect.height);

		if (client->supports_zrle) {
			msg3.encoding_type = htonl(RFB_ENCODING_ZRLE);
			client->io->write(&msg3, sizeof(msg3));
			tx_frameupdate_zrle(client, rect.x, rect.y, rect.width, rect.height);
		} else {
			msg3.encoding_type = htonl(RFB_ENCODING_RAW);
			client->io->write(&msg3, sizeof(msg3));
			tx_frameupdate_raw(client, rect.x, rect.y, rect.width, rect.height);
		}
	}
}

static void framebuffer_update_size(StupidClient* client) {
	frame_update_header_t msg2;
	msg2.type = RFB_FRAMEBUFFER_UPDATE;
	msg2.num_rects = htons(1);
	client->io->write(&msg2, sizeof(msg2));

	auto priv = client->server->_p;

	frame_update_rect_header_t msg3;
	msg3.x = htons(0);
	msg3.y = htons(0);
	msg3.w = htons(priv->fb_width);
	msg3.h = htons(priv->fb_height);
	msg3.encoding_type = htonl(RFB_ENCODING_DESKTOPSIZE_PSEUDO);
	client->io->write(&msg3, sizeof(msg3));
}

void set_pixel_format(StupidClient* client) {
	// +--------------+--------------+--------------+
	// | No. of bytes | Type [Value] | Description  |
	// +--------------+--------------+--------------+
	// | 1            | U8 [0]       | message-type |
	// | 3            |              | padding      |
	// | 16           | PIXEL_FORMAT | pixel-format |
	// +--------------+--------------+--------------+
 	char buf[16];
	client->io->read(buf, 3);

	client->io->read(&client->pixel_format, sizeof(client->pixel_format));
	client->pixel_format.red_max = ntohs(client->pixel_format.red_max);
	client->pixel_format.green_max = ntohs(client->pixel_format.green_max);
	client->pixel_format.blue_max = ntohs(client->pixel_format.blue_max);

	STUPID_LOG(TRACE_MSG, "format: bpp:%d depth:%d be:%d truecolor:%d rmax:%d gmax:%d bmax:%d rshift:%d gshift:%d, bshift:%d",
		   client->pixel_format.bpp,
		   client->pixel_format.depth,
		   client->pixel_format.big_endian,
		   client->pixel_format.truecolor,
		   client->pixel_format.red_max,
		   client->pixel_format.green_max,
		   client->pixel_format.blue_max,
		   client->pixel_format.red_shift,
		   client->pixel_format.green_shift,
		   client->pixel_format.blue_shift
	);
}

void set_encoding(StupidClient* client) {
	uint16_t count;
	// char buf[16];
	// +--------------+--------------+---------------------+
	// | No. of bytes | Type [Value] | Description         |
	// +--------------+--------------+---------------------+
	// | 1            | U8 [2]       | message-type        |
	// | 1            |              | padding             |
	// | 2            | U16          | number-of-encodings |
	// +--------------+--------------+---------------------+
	client->io->read(&count, 1);
	client->io->read(&count, 2);
	count = ntohs(count);
	STUPID_LOG(TRACE_INFO,"%d encodings", count);
	while (count--) {
		int32_t encoding;
		// +--------------+--------------+---------------+
		// | No. of bytes | Type [Value] | Description   |
		// +--------------+--------------+---------------+
		// | 4            | S32          | encoding-type |
		// +--------------+--------------+---------------+
		client->io->read(&encoding, 4);

		encoding = (int32_t)ntohl(encoding);
		switch (encoding) {
			case RFB_ENCODING_RAW:                STUPID_LOG(TRACE_INFO, "   encoding RAW"); break;
			case RFB_ENCODING_COPYRECT:           STUPID_LOG(TRACE_INFO, "   encoding COPYRECT"); break;
			case RFB_ENCODING_RRE:                STUPID_LOG(TRACE_INFO, "   encoding RRE"); break;
			case RFB_ENCODING_HEXTILE:            STUPID_LOG(TRACE_INFO, "   encoding HEXTILE"); break;
			case RFB_ENCODING_TRLE:               STUPID_LOG(TRACE_INFO, "   encoding TRLE"); break;
			case RFB_ENCODING_ZRLE:               STUPID_LOG(TRACE_INFO, "   encoding ZRLE"); client->supports_zrle=true;  break;
			case RFB_ENCODING_CURSOR_PSEUDO:      STUPID_LOG(TRACE_INFO, "   encoding CURSOR"); break;
			case RFB_ENCODING_DESKTOPSIZE_PSEUDO: STUPID_LOG(TRACE_INFO, "   encoding DESKTOP"); client->supports_fb_geometry_change = true; break;
			default: STUPID_LOG(TRACE_INFO, "   encoding UNKNOWN %d)", encoding);
		}
	}
}

static void pointer_event(StupidClient* client) {
	auto priv = client->server->_p;
	pointer_event_t msg;
	client->io->read(&msg, sizeof(msg));
	msg.x = ntohs(msg.x);
	msg.y = ntohs(msg.y);
	STUPID_LOG(TRACE_MSG, "Pointer event  mask:0x%02X  x:%d y:%d", msg.button_mask, msg.x, msg.y);
	priv->cb->pointerEvent(client, msg.x, msg.y, msg.button_mask);

}

// +--------------+--------------+--------------+
// | No. of bytes | Type [Value] | Description  |
// +--------------+--------------+--------------+
// | 1            | U8 [6]       | message-type |
// | 3            |              | padding      |
// | 4            | U32          | length       |
// | length       | U8 array     | text         |
// +--------------+--------------+--------------+
void client_cut_text(StupidClient* client) {
	unsigned char dummy[4096];
	client->io->read(dummy, 3);
	uint32_t len;
	client->io->read(&len, sizeof(len));
	len = ntohl(len);
	client->io->read(dummy, len);
	dummy[len] = 0;
	STUPID_LOG(TRACE_MSG, "SERVER CUT: %s\n", dummy);
}

#ifdef HAS_OPENSSL
void handleErrors(void) {
	// Handle errors here. You can customize this function based on your needs.
	STUPID_LOGE("An error occurred");
	exit(EXIT_FAILURE);
}

static void encryptDES(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key,
                unsigned char *ciphertext, int *ciphertext_len)
{
	EVP_CIPHER_CTX *ctx;

	OSSL_PROVIDER* legacy = NULL;
	if ((legacy == nullptr) && (OSSL_PROVIDER_available(NULL, "legacy") == 0))
		legacy = OSSL_PROVIDER_try_load(NULL, "legacy", 1);

	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();
	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_NO_PADDING);

	if (EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, nullptr) != 1)
		handleErrors();

	auto dst = ciphertext;
	int outl;
	if (EVP_EncryptUpdate(ctx, ciphertext, &outl, plaintext, plaintext_len) != 1)
		handleErrors();

	plaintext_len -= outl;
	dst += outl;
	*ciphertext_len += outl;

	if (EVP_EncryptFinal_ex(ctx, dst, &outl) != 1)
		handleErrors();
	*ciphertext_len += outl;

	EVP_CIPHER_CTX_free(ctx);
	OSSL_PROVIDER_unload(legacy);
}

static unsigned char reverse_bits(unsigned char b) {
	unsigned char r = 0;
	unsigned int byte_len = 8;
	while (byte_len--) {
		r <<= 1;
		r |= b & 1;
		b >>= 1;
	}

	return r;
}

static bool vnc_auth(StupidClient* client) {
	auto priv = client->server->_p;
	RAND_bytes(client->challenge, sizeof(client->challenge));

	client->io->write(client->challenge, sizeof(client->challenge));
	client->io->read(client->response, sizeof(client->response));

	// TX random 16 byte challenge
	// RX 16 byte response

	uint32_t security_result = htonl(RFB_STATUS_OK);
	if (!priv->cb->clientAuth(client)) {
		uint32_t security_result = htonl(RFB_STATUS_FAILED);
		const char* error_string = "you entered a stupid password";
		client->io->write(&security_result, sizeof(security_result));
		uint32_t error_string_length = htonl(strlen(error_string));
		client->io->write(&error_string_length, sizeof(error_string_length));
		client->io->write(error_string, strlen(error_string));
		return false;
	}

	client->io->write(&security_result, sizeof(security_result));
	return true;
}

bool stupidvnc_check_passwd(StupidClient *client, const std::string &passwd) {
	unsigned char challenge_encrypted[16];
	int challenge_encrypted_len = 0;

	// Apparently each byte must be reversed
	// https://catonmat.net/curious-case-of-des-algorithm
	//
	// The documentation did not say!!! WTF!!
	unsigned char weird_passwd[8] = {};
	int l = passwd.size();
	if (l > 8)
		l = 8;
	for (auto i=0; i<l; i++)
		weird_passwd[i] = reverse_bits(passwd[i]);

	encryptDES(client->challenge, sizeof(client->challenge), (unsigned char*)weird_passwd, challenge_encrypted, &challenge_encrypted_len);

	// for (auto i=0; i<challenge_encrypted_len; i++)
	// 	printf("0x%02x ", challenge_encrypted[i]);
	// printf("\n");
	assert(challenge_encrypted_len == 16);

	return memcmp(challenge_encrypted, client->response, sizeof(challenge_encrypted)) == 0;
}
#else
static bool vnc_auth([[maybe_unused]] StupidClient* client) {
	return false;
}

bool stupidvnc_check_passwd([[maybe_unused]] StupidClient *client, [[maybe_unused]] const std::string &passwd) {
	return false;
}
#endif

static bool client_handshake(StupidClient* client) {
	auto priv = client->server->_p;
	static const char* ident = "RFB 003.008\n";
	client->io->write(ident, 12);

	char buf[1024];
	int ret = client->io->read(buf, 12);
	buf[ret] = 0;
	STUPID_LOG(TRACE_INFO, "Client: %s", buf);

	int security_types_len = 0;
	uint8_t security_types[8];

	security_types[0] = 0;

	// No authentication
	if (!priv->cb->requirePassword) {
		security_types[0]++;
		security_types[++security_types_len] = RFB_SEC_NONE;
	}

	// VNC auth
	security_types[0]++;
	security_types[++security_types_len] = RFB_SEC_VNC;

	client->io->write(security_types, security_types_len+1);

	uint8_t selected_security;
	ret = client->io->read(&selected_security, 1);
	STUPID_LOG(TRACE_INFO, "Client selected security type %d", selected_security);

	// If sec!=null
	// server send 16 byte random challenge
	// client encrypts using DES+password. password is 8 bytes 0 padded

	bool auth_ok = false;
	if (selected_security == RFB_SEC_VNC) {
		auth_ok = vnc_auth(client);
	}

	if (selected_security == RFB_SEC_NONE) {
		uint32_t security_result = RFB_STATUS_OK;
		client->io->write(&security_result, sizeof(security_result));
		auth_ok = true;
	}

	if (!auth_ok)
		return false;

	// Shared is 0 if the server should disconnect other clients
	ret = client->io->read(buf, 1);
	STUPID_LOG(TRACE_INFO, "Client - shared %d", buf[0]);

	struct server_init_msg_t server_init_msg;
	const char* name = "STUPIDRFB";
	server_init_msg.width = htons(priv->fb_width);
	server_init_msg.height = htons(priv->fb_height);
	server_init_msg.namelength = htonl( strlen(name));
	client->io->write(&server_init_msg, sizeof(server_init_msg));
	client->io->write(name, strlen(name));

	priv->cb->clientConnected(client);
	return true;
}

static void stupid_thread(void* arg) {
	auto client = (StupidClient*)arg;
	auto server = client->server;
	auto priv = server->_p;

	client->io->handshake();
	if (!client_handshake(client)) {
		delete client;
		return;
	}

	priv->server_mutex.lock();
	priv->allClients.push_back(client);
	priv->server_mutex.unlock();

	while (!client->disconnect) {
		priv->server_mutex.lock();
		if (priv->fb_geometry_changed) {
			priv->fb_geometry_changed = false;

			if (client->supports_fb_geometry_change) {
				framebuffer_update_size(client);
			}

			// Clear direty rects and just dirty the complete fb.
			client->mutex.lock();
			client->dirtyRects.clear();
			client->dirtyRects.push_back({0, 0, priv->fb_width, priv->fb_height});
			client->mutex.unlock();
		}
		priv->server_mutex.unlock();

		if (client->wants_framebuffer) {
			priv->server_mutex.lock();
			framebuffer_update(client);
			priv->server_mutex.unlock();
		}

		uint8_t type;
		STUPID_LOG(TRACE_COMM, "read start\n");
		int ret = client->io->read(&type, 1, false);
		STUPID_LOG(TRACE_COMM, "read end ret: %d", ret);

		if (ret == -1)
			continue;

		if (ret == 0) {
			STUPID_LOG(TRACE_CONNECITONS, "Disconnected");
			break;
		}

		switch(type) {
			case RFB_SET_PIXEL_FORMAT:
				STUPID_LOG(TRACE_MSG ,"RFB_SET_PIXEL_FORMAT");
				set_pixel_format(client);
			break;
			case RFB_SET_ENCODINGS:
				STUPID_LOG(TRACE_MSG, "RFB_SET_ENCODINGS");
				set_encoding(client);
				break;
			case RFB_FRAME_UPDATE_REQUEST:
				frame_update_request(client);
				break;
			case RFB_KEY_EVENT:
				key_event(client);
				break;
			case RFB_POINTER_EVENT:
				pointer_event(client);
				break;
			case RFB_CLIENT_CUT_TEXT:
				STUPID_LOG(TRACE_MSG, "RFB_CLIENT_CUT_TEXT\n");
				client_cut_text(client);
				break;
			default:
				assert(false);
		}

	}
	priv->server_mutex.lock();
	auto it = std::find(priv->allClients.begin(), priv->allClients.end(), client);
	priv->allClients.erase(it);
	priv->server_mutex.unlock();
	priv->cb->clientDisconnected(client);
	delete client;
}

void stupidvnc_init(StupidvncServer* server, StupidvncCallbacks* cb) {
	static StupidvncCallbacks default_cb;
	auto priv = new StupidvncServerPrivate;
	server->_p = priv;
	priv->cb = cb ? cb : &default_cb;
}

void stupidvnc_free(StupidvncServer *server) {
	delete server->_p;
	server->_p = nullptr;
}

static void server_run(void* arg) {
	auto server = (StupidvncServer*)arg;
	auto priv = server->_p;
	int server_sock = bind_server_socket(server->port);
	// int server_sock = bind_server_socket(8080);

	while (!priv->quit) {
		fd_set read_fds;
		FD_ZERO(&read_fds);
		FD_SET(server_sock, &read_fds);

		auto ret = select(server_sock+1, &read_fds, nullptr, nullptr, nullptr);
		if (ret == 1) {
			int sock = accept(server_sock, nullptr, 0);

			IStupidIO* io = new RAWIO(sock);
			if(server->use_websocket)
					io = get_ws_io(io);
			auto client = new StupidClient(io);
			client->server = server;
			client->dirtyRects.push_back({0, 0, priv->fb_width, priv->fb_height});

			auto th = new std::thread(stupid_thread, client);
			th->detach();
		}
	}
}

void stupidvnc_start(StupidvncServer* server) {
	auto priv = server->_p;
	assert(!priv->thread.joinable());
	priv->quit = false;
	priv->thread = std::thread(server_run, server);
}

void stupidvnc_stop(StupidvncServer* server) {
	auto priv = server->_p;
	assert(priv->thread.joinable());
	priv->quit = true;
	priv->thread.join();
}

void stupidvnc_dirty(StupidvncServer* server, int x, int y, unsigned int width, unsigned int height) {
	auto priv = server->_p;
	priv->server_mutex.lock();
	if (width == 0) width = priv->fb_width;
	if (height == 0) height = priv->fb_height;
	for (auto c : priv->allClients) {
		c->mutex.lock();
		bool add_new_rect = true;
		for (auto & rect : c->dirtyRects) {

			// Simple skip of duplicates
			if (x >= rect.x && (rect.x + rect.width) >= (x + width) &&
			    y >= rect.y && (rect.y + rect.height) >= (y + height)) {
				add_new_rect =  false;
				break;
			}
		}
		if (add_new_rect) {
			STUPID_LOG(TRACE_DIRTY, "Marking dirty rect: %d,%d,%d,%d", x, y, width, height);
			c->dirtyRects.push_back({x, y, width, height});
		}
		c->mutex.unlock();
	}
	priv->server_mutex.unlock();
}

void stupidvnc_set_framebuffer(StupidvncServer* server, uint32_t *fb, unsigned int width, unsigned int height) {
	auto priv = server->_p;
	priv->server_mutex.lock();
	priv->framebuffer = fb;

	if (priv->fb_width != width) {
		priv->fb_geometry_changed = true;
		priv->fb_width = width;
	}

	if (priv->fb_height != height) {
		priv->fb_geometry_changed = true;
		priv->fb_height = height;
	}
	priv->server_mutex.unlock();
}

void stupidvnc_disconnect(StupidClient *client) {
	client->disconnect = true;
}
