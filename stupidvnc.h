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

#pragma once
#include <inttypes.h>
#include <string>

#define STUPIDVNC_EXPORT __attribute__ ((visibility ("default")))

#define RFB_MOUSE_LEFT       (1<<0)
#define RFB_MOUSE_MIDDLE     (1<<1)
#define RFB_MOUSE_RIGHT      (1<<2)
#define RFB_MOUSE_WHEEL_UP   (1<<3)
#define RFB_MOUSE_WHEEL_DOWN (1<<4)

struct StupidClient;
struct STUPIDVNC_EXPORT StupidvncCallbacks {
	bool requirePassword = false;

	virtual ~StupidvncCallbacks() {}

	virtual void pointerEvent(StupidClient* client, int x, int y, int button_mask);
	virtual void keyEvent(StupidClient* client, unsigned char key, bool down);
	virtual void framebufferUpdate(StupidClient* client);
	virtual void clientConnected(StupidClient* client);
	virtual void clientDisconnected(StupidClient* client);
	virtual bool clientAuth(StupidClient* client);
};

STUPIDVNC_EXPORT bool stupidvnc_check_passwd(StupidClient* client, const std::string& passwd);

struct StupidvncServer;
STUPIDVNC_EXPORT StupidvncServer* stupidvnc_init(StupidvncCallbacks* cb);
STUPIDVNC_EXPORT void stupidvnc_set_framebuffer(StupidvncServer* server, uint32_t *fb, unsigned int width, unsigned int height);
STUPIDVNC_EXPORT void stupidvnc_disconnect(StupidClient* client);
STUPIDVNC_EXPORT void stupidvnc_dirty(StupidvncServer* server, int x, int y, unsigned int width, unsigned int height);
STUPIDVNC_EXPORT void stupidvnc_start(StupidvncServer* server);
STUPIDVNC_EXPORT void stupidvnc_stop(StupidvncServer* server);

// Default implementation of StupidvncCallbacks
inline void StupidvncCallbacks::pointerEvent(StupidClient *, int, int, int) {}
inline void StupidvncCallbacks::framebufferUpdate(StupidClient* ) { }
inline void StupidvncCallbacks::keyEvent(StupidClient *, unsigned char, bool) {}
inline void StupidvncCallbacks::clientConnected(StupidClient *) {}
inline void StupidvncCallbacks::clientDisconnected(StupidClient *) {}
inline bool StupidvncCallbacks::clientAuth(StupidClient *) { return true; }
