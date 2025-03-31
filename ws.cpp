#include "ws.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <string>
#include <cinttypes>
#include <cstdio>
#include <cassert>
#include <algorithm>

#include <openssl/sha.h>

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

// https://www.rfc-editor.org/rfc/rfc6455.html

static constexpr bool TRACE_WS_READ = false;
static constexpr bool TRACE_WS_WRITE = false;
static constexpr bool TRACE_WS_HANDSHAKE = true;

static char* base64_encode(const unsigned char* input, size_t input_len) {
	const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t output_len = 4 * ((input_len + 2) / 3);  // Calculate the length of the Base64 encoded string
	char* output = (char*)malloc(output_len + 1);     // +1 for null terminator
	if (output == NULL) {
		perror("Memory allocation failed");
		exit(EXIT_FAILURE);
	}

	size_t i, j;
	for (i = 0, j = 0; i < input_len; i += 3, j += 4) {
		output[j] = base64_chars[(input[i] >> 2) & 0x3F];
		output[j + 1] = base64_chars[((input[i] & 0x3) << 4) | ((i + 1 < input_len) ? ((input[i + 1] >> 4) & 0xF) : 0)];
		output[j + 2] = (i + 1 < input_len) ? base64_chars[((input[i + 1] & 0xF) << 2) | ((i + 2 < input_len) ? ((input[i + 2] >> 6) & 0x3) : 0)] : '=';
		output[j + 3] = (i + 2 < input_len) ? base64_chars[input[i + 2] & 0x3F] : '=';
	}

	output[j] = '\0';  // Null-terminate the string
	return output;
}

static char* sha1_base64_encode(const char* input) {
	// Compute SHA-1 hash
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	SHA1((const unsigned char*)input, strlen(input), sha1_hash);

	// Base64 encode the SHA-1 hash
	char* base64_encoded = base64_encode(sha1_hash, SHA_DIGEST_LENGTH);
	return base64_encoded;
}

#define WS_FRAME_TYPE_CONTINUATION 0x0
#define WS_FRAME_TYPE_TEXT         0x1
#define WS_FRAME_TYPE_BINARY       0x2
#define WS_FRAME_TYPE_CLOSE        0x8
#define WS_FRAME_TYPE_PING         0x9
#define WS_FRAME_TYPE_PONG         0xA

static int write_websocket_header(unsigned char* header, unsigned int len) {
	header[0] = 0;
	header[0] = 0x80; // FIN
	header[0] |= WS_FRAME_TYPE_BINARY;

	int len_bytes = 0;
	if (len < 126) { // Small header
		header[1] = len;
	} else { // Extended
		if (len <= 0xffff) {
			header[1] = 126;
			len_bytes = 2;
			uint16_t len16 = ntohs(len);
			memcpy(&header[2], &len16, len_bytes);
		} else {
			header[1] = 127;
			len_bytes = 8;
			// uint64_t len64 = ntohl(len);
			uint64_t len64 = ntohl(len);
			len64 <<= 32;
			memcpy(&header[2], &len64, len_bytes);
		}
	}

	// header[1] |= 0x80; // MASK

	return 2 + len_bytes;
}


void ws_handshake(IStupidIO* io) {
	STUPID_LOG(TRACE_WS_HANDSHAKE, "Waiting for header from client");
	std::string header;
	char buffer[1024];
	do {
		auto len = io->read(buffer, sizeof(buffer));
		if (len == 0)
			return;
		header.append(buffer, len);
		if (header.size() > 1024*1024) // Limit size to 1M
			return;
	} while (header.find("\r\n\r\n") == std::string::npos);

	STUPID_LOG(TRACE_WS_HANDSHAKE, "Received header from client: %s", header.c_str());

	std::string sec;
	const char* sec_ws_str = "Sec-WebSocket-Key: ";
	auto sec_ws_key_pos = header.find(sec_ws_str);
	if (sec_ws_key_pos == std::string::npos)
		return;

	auto crnl_pos = header.find("\r\n", sec_ws_key_pos);
	auto sec_str_len = crnl_pos - (sec_ws_key_pos + strlen(sec_ws_str));
	sec.assign(header.substr(sec_ws_key_pos + strlen(sec_ws_str), sec_str_len));
	STUPID_LOG(TRACE_WS_HANDSHAKE, "\"%s\"\n", sec.c_str());

	unsigned char response[1024];
	sec += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	auto response_sec = sha1_base64_encode(sec.c_str());


	int len;
	if (strstr(buffer, "Sec-WebSocket-Protocol: binary"))
		len = snprintf((char*)response, sizeof(response), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: binary\r\n\r\n", response_sec);
	else
		len = snprintf((char*)response, sizeof(response), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", response_sec);
	free(response_sec);

	STUPID_LOG(TRACE_WS_HANDSHAKE, "\"%s\"", response);

	io->write(response, len, FlushMode::FLUSH);
}


#define MAX_WS_HEADER_LEN 20

struct WSIO : IStupidIO {
	bool please_close = false;

	WSIO(IStupidIO* io) {
		_io = io;
		ws_handshake(_io);
	}

	~WSIO() {
		delete _io;
	}

	int read_websocket_header(bool block) {
		int hlen = 0;
		unsigned char header[MAX_WS_HEADER_LEN];
		int ret = _io->read(header + 0, 1, block); // Read minimum header
		if (ret == -1)
			return ret;

		ret = _io->read(header + 1, 1); // Read minimum header

		STUPID_LOG(TRACE_WS_READ, "Read1 ret:%d", ret);
		if (ret <= 0)
			return ret;

		hlen += ret;

		bool fin = header[0] & 0x80;
		unsigned int opcode = header[0] & 0x0f;
		int len = header[1] & 0x7f;
		bool masked = header[1] & 0x80;
		assert(len != 126 && len != 127); // We do not care about larger headers.
		STUPID_LOG(TRACE_WS_READ, "WS: fin:%d  len:%d mask:%d ret:%d opcode:%u", fin, len, masked, ret, opcode);

		assert(masked);

		ret = _io->read(&_masking_key, 4);

		STUPID_LOG(TRACE_WS_READ, "Read2 ret:%d\n", ret);
		assert (ret == 4);
		hlen += ret;

		// fflush(0);
		_payload_left = len;
		_payload_idx = 0;

		if (opcode == 8)
			please_close = true;
		return hlen;
	}



	int read(void* dst, unsigned int len, bool block) override {
		auto cdst = (unsigned char*)dst;
		int bytes_read = 0;
		int ret;
		do {
			if (_payload_left == 0) {
				ret = read_websocket_header(block);
				STUPID_LOG(TRACE_WS_READ, "Read header ret:%d\n", ret);
				if (ret <= 0)
					return ret;
				if (please_close) {
					STUPID_LOG(TRACE_WS_READ, "WS: close frame");
					return 0;
				}
			}

			ret = _io->read(cdst, len);

			for (auto i=0; i<ret; i++)
				cdst[i] ^= _masking_key[(_payload_idx + i) % 4];

			_payload_idx += ret;
			cdst += ret;
			len -= ret;
			_payload_left -= ret;
			bytes_read += ret;
		} while (len > 0);

		if (bytes_read == 0)
			return ret;
		return bytes_read;
	}

	void flush() {
		if (_txQ_write_ptr == 0)
			return;

		unsigned char header[MAX_WS_HEADER_LEN];
		int header_len = write_websocket_header(header, _txQ_write_ptr);

		STUPID_LOG(TRACE_WS_WRITE, "WS frame write - len %d", _txQ_write_ptr);
		_io->write(header, header_len, FlushMode::NOFLUSH);
		_io->write(_txQ, _txQ_write_ptr, FlushMode::FLUSH);
		_txQ_write_ptr = 0;
	}

	void close() override {
		_io->close();
	}

private:
	IStupidIO* _io;

	unsigned int _payload_left = 0;
	unsigned int _payload_idx = 0;
	unsigned char _masking_key[4];
};


IStupidIO* get_ws_io(IStupidIO* io) {
	return new WSIO(io);
}
