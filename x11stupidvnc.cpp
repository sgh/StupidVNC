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

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>
#include <X11/extensions/Xdamage.h>
#include <stdio.h>
#include <stdlib.h>

#include <cstring>

#include <inttypes.h>

#include <signal.h>
#include <openssl/evp.h>


Display* display;


int fb_width = 0;
int fb_height = 0;
static uint32_t* fb = nullptr;

StupidvncServer* server;

void fetchRegion(Window window, int x, int y, int width, int height) {
	XImage* image = XGetImage(display, window, x, y, width, height, AllPlanes, ZPixmap);

	if (image == NULL) {
		fprintf(stderr, "Failed to capture framebuffer.\n");
		return;
	}

	// Write pixel data to file
	for (int iy = 0; iy < height; iy++) {
		for (int ix = 0; ix < width; ix++) {
			unsigned long pixel = XGetPixel(image, ix, iy);
			unsigned char r = (pixel >> 16) & 0xFF;
			unsigned char g = (pixel >> 8) & 0xFF;
			unsigned char b = pixel & 0xFF;
			// fprintf(file, "%d %d %d ", r, g, b);
			fb[(y + iy)*fb_width + x + ix] = r<<16 | g <<8 | b;
		}
		// fprintf(file, "\n");
	}

	// Remember to free the image data after use
	XDestroyImage(image);
}


// void sendKeyPress(Window window, KeySym key)
// {
// 	KeyCode keycode = XKeysymToKeycode(display, key);
// 	XTestFakeKeyEvent(display, keycode, True, 0);
// 	XTestFakeKeyEvent(display, keycode, False, 0);
// 	XFlush(display);
// }


void captureFramebufferDamaged(Damage damage, Window window) {
	XserverRegion region = XFixesCreateRegion(display, NULL, 0);
	XDamageSubtract(display, damage, None, region);

	 int nrect;

	 if (!XFixesFetchRegion(display, region, &nrect)) {
		 fprintf(stderr, "Failed to fetch region.\n");
		 XFixesDestroyRegion(display, region);
		 return;
	 }

	printf("Damaged region: %d rectangles\n", nrect);

	XRectangle *rectangles = XFixesFetchRegion(display, region, &nrect);

	// Iterate over the damaged rectangles
	for (int i = 0; i < nrect; i++) {
		int x = rectangles[i].x;
		int y = rectangles[i].y;
		int width = rectangles[i].width;
		int height = rectangles[i].height;

		printf("Rect %d: x=%d, y=%d, width=%d, height=%d\n", i+1, x, y, width, height);

		// Now you can capture the framebuffer for the damaged region
		// using XGetImage or other methods as needed
		fetchRegion(window, x, y, width, height);
		stupidvnc_dirty(server, x, y, width, height);
	}

	XFree(rectangles);
	XFixesDestroyRegion(display, region);
	printf("Done\n");
}


void damageNotifyEvent(XEvent *event) {

	XDamageNotifyEvent *damageEvent = (XDamageNotifyEvent *)event;
	Window window = damageEvent->drawable;
	Damage damage = damageEvent->damage;

	XWindowAttributes attr;
	XGetWindowAttributes(display, window, &attr);
	if (!fb || attr.width!=fb_width || attr.height!=fb_height) {
		auto new_fb = new uint32_t[attr.width * attr.height];
		fb_width = attr.width;
		fb_height = attr.height;
		stupidvnc_set_framebuffer(server, new_fb, fb_width, fb_height);
		if (fb)
			delete[] fb;
		fb = new_fb;
	}

	captureFramebufferDamaged(damage, window);
	XDamageSubtract(display, damage, None, None);
}

int main(int argc, char** argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <window_id>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	signal(SIGPIPE, SIG_IGN);
	OpenSSL_add_all_algorithms();

	server = stupidvnc_init(nullptr);

    Window window = strtoull(argv[1], NULL, 16); // Parse window ID as hexadecimal

	display = XOpenDisplay(NULL);
	if (display == NULL) {
		fprintf(stderr, "Unable to open display.\n");
		exit(EXIT_FAILURE);
	}

	stupidvnc_start(server);

	int damageEventBase, damageErrorBase;
		if (!XDamageQueryExtension(display, &damageEventBase, &damageErrorBase)) {
		fprintf(stderr, "XDamage extension not available.\n");
		exit(EXIT_FAILURE);
	}

	// Create a damage handle on the window
	Damage damage = XDamageCreate(display, window, XDamageReportNonEmpty);

	// Select Damage events on the root window
	XDamageSubtract(display, damage, None, None);
	XSelectInput(display, window, XDamageNotify);

	XEvent event;
	while (1) {
		XNextEvent(display, &event);
		if (event.type == damageEventBase + XDamageNotify) {
			damageNotifyEvent(&event);
		}

	}

	// Create event structure for injection
	// XEvent event;
	// memset(&event, 0, sizeof(event));
	// event.type = KeyPress;
	// event.xkey.window = window; // Specify the target window
	// event.xkey.keycode = XKeysymToKeycode(display, XK_A);
	// event.xkey.state = 0;
	// XSendEvent(display, window, True, KeyPressMask, &event);

	// XFlush(display);

	XCloseDisplay(display);

	return 0;
}
