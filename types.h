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
#include <string.h>

#include "stupidvnc.h"

enum class FlushMode {
	NOFLUSH,
	FLUSH ,
};

struct IStupidIO {
	virtual ~IStupidIO() {}

	virtual void handshake() {}
	virtual int read(void* dst, unsigned int len, bool block = true) = 0;
	virtual void write(const void* src, unsigned int len, FlushMode flushmode) final;
	virtual void close() = 0;
	virtual void flush() = 0;

	unsigned char _txQ[256*1024];
	unsigned int _txQ_write_ptr;
};

inline void IStupidIO::write(const void *src, unsigned int len, FlushMode flushmode)
{
	auto csrc = (const char*)src;
	while (len > 0) {
		unsigned int remaining_space = sizeof(_txQ) - _txQ_write_ptr;
		if (remaining_space == 0)
			flush();

		auto chunk_size = std::min(remaining_space, len);
		memcpy(&_txQ[_txQ_write_ptr], csrc, chunk_size);
		_txQ_write_ptr += chunk_size;
		len -= chunk_size;
		csrc += chunk_size;
	}

	if (flushmode == FlushMode::FLUSH)
		flush();
}
