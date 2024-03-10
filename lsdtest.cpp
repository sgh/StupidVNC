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

#include <math.h>
#include <signal.h>

#ifdef HAS_OPENSSL
#include <openssl/evp.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#define FRAMEBUFFER_WIDTH  800
#define FRAMEBUFFER_HEIGHT 600

double tspeed = 0.05;
int center_x = FRAMEBUFFER_WIDTH / 2;
int center_y = FRAMEBUFFER_HEIGHT / 2;

double distmulR = 0.05;
double distmulG = 0.03;
double distmulB = 0.01;

uint32_t framebuffer[FRAMEBUFFER_WIDTH * FRAMEBUFFER_HEIGHT]; // RGB
uint32_t framebuffer_red[FRAMEBUFFER_WIDTH/2 * FRAMEBUFFER_HEIGHT/2];
uint32_t framebuffer_green[FRAMEBUFFER_WIDTH/4 * FRAMEBUFFER_HEIGHT/4];
uint32_t framebuffer_blue[FRAMEBUFFER_WIDTH/8 * FRAMEBUFFER_HEIGHT/8];

void drawSinePattern(double t) {
	// Loop through each pixel in the framebuffer
	for (int y = 0; y < FRAMEBUFFER_HEIGHT; y++) {
		for (int x = 0; x < FRAMEBUFFER_WIDTH; x++) {

			auto distX = fabs(x - center_x);
			auto distY = fabs(y - center_y);
			auto dist2d = sqrt(distX*distX + distY*distY);

			// Calculate the sine value based on the x-coordinate
			double sineValueRed = sin(dist2d * distmulR + t);
			double sineValueGreen = sin(dist2d * distmulG + t);
			double sineValueBlue = sin(dist2d * distmulB + t);

			// Scale the sine value to the range [0, 255] for the alpha channel
			uint32_t red = (uint32_t)((sineValueRed + 1.0) * 0.5 * 255);
			uint32_t blue = (uint32_t)((sineValueBlue + 1.0) * 0.5 * 255);
			uint32_t green = (uint32_t)((sineValueGreen + 1.0) * 0.5 * 255);
			// blue = 0;
			// green = 0;

			// Create the ARGB color value (assuming a white background)
			uint32_t pixelColor =  (red<<16)  | (green<<8) | blue;

			// Set the pixel color in the framebuffer
			framebuffer[y * FRAMEBUFFER_WIDTH + x] = pixelColor;
		}
	}
}


struct VNCCallbacks : public StupidvncCallbacks {
	int fbidx = 0;
	StupidvncServer* server;

	void pointerEvent([[maybe_unused]] StupidClient* client, int x, int y, int button_mask) override {
		if (button_mask == RFB_MOUSE_LEFT) {
			center_x = x;
			center_y = y;
		}
		if (button_mask == RFB_MOUSE_WHEEL_UP) {
			distmulG += 0.01;
		}
		if (button_mask == RFB_MOUSE_WHEEL_DOWN) {
			distmulG -= 0.01;
		}
	}


	void keyEvent([[maybe_unused]] StupidClient* client, unsigned char key, bool down) override {
		if (!down)
			return;
		if (key == 'a') distmulR+= 0.001;
		if (key == 'z') distmulR-= 0.001;
		if (key == '+') tspeed += 0.01;
		if (key == '-') tspeed -= 0.01;
		if (tspeed < 0.0)
			tspeed = 0.0;

		if (key == '\t') {
			fbidx++;
			if (fbidx > 3)
				fbidx = 0;
			switch (fbidx) {
				case 0 : stupidvnc_set_framebuffer(server, framebuffer, FRAMEBUFFER_WIDTH, FRAMEBUFFER_HEIGHT); break;
				case 1 : stupidvnc_set_framebuffer(server, framebuffer_red, FRAMEBUFFER_WIDTH/2, FRAMEBUFFER_HEIGHT/2); break;
				case 2 : stupidvnc_set_framebuffer(server, framebuffer_green, FRAMEBUFFER_WIDTH/4, FRAMEBUFFER_HEIGHT/4); break;
				case 3 : stupidvnc_set_framebuffer(server, framebuffer_blue, FRAMEBUFFER_WIDTH/8, FRAMEBUFFER_HEIGHT/8); break;
			}
		}
	}

	bool clientAuth([[maybe_unused]] StupidClient *client) override {
		// return stupidvnc_check_passwd(client, "1234");
		return true;
	}
};


int main() {
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
#ifdef HAS_OPENSSL
	OpenSSL_add_all_algorithms();
#endif

#ifdef _WIN32
	WSADATA wsaData;
	// Initialize Winsock
	auto res = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (res != 0) {
		printf("WSAStartup failed with error: %d\n", res);
		return 1;
	}
#endif

	for (auto i=0; i<FRAMEBUFFER_HEIGHT/2*FRAMEBUFFER_WIDTH/2; i++)
		framebuffer_red[i] = 0xff << 16;

	for (auto i=0; i<FRAMEBUFFER_HEIGHT/4*FRAMEBUFFER_WIDTH/4; i++)
		framebuffer_green[i] = 0xff << 8;

	for (auto i=0; i<FRAMEBUFFER_HEIGHT/8*FRAMEBUFFER_WIDTH/8; i++)
		framebuffer_blue[i] = 0xff;

	VNCCallbacks cb;
	// cb.requirePassword = true;
	StupidvncServer s;
	stupidvnc_init(&s, &cb);
	stupidvnc_set_framebuffer(&s, framebuffer, FRAMEBUFFER_WIDTH, FRAMEBUFFER_HEIGHT);

	cb.server = &s;
	stupidvnc_start(&s);

	for (;;) {
#ifndef _WIN32
		usleep(100000);
#else
		Sleep(100);
#endif
		static double t;
		t += tspeed;
		if (t >= 2*M_PI)
			t -= 2*M_PI;
		drawSinePattern(t);
		stupidvnc_dirty(&s, 0, 0, 0, 0);
	}
}
