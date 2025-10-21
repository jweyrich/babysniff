#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif

// Prevent Windows headers from defining min and max macros
#ifndef NOMINMAX
#	define NOMINMAX
#endif

#include "channel_ops_common.h"
#include "channel_ops.h"
#include "compat/network_compat.h"
#include "config.h"
#include "log.h"
#include "macros.h"
#include "proto_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <wchar.h>

#include <iphlpapi.h>
#include <mstcpip.h>

// Windows-specific includes
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Initialize WinSock2
static int windows_init_winsock(void) {
	static int initialized = 0;
	if (initialized)
		return 0;

	WSADATA wsaData;
	int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (result != 0) {
		return -1;
	}
	initialized = 1;
	return 0;
}

// Helper function to compare wide string with multi-byte string
static bool wide_string_matches(const wchar_t *wide_str, const char *mb_str) {
	if (wide_str == NULL && mb_str == NULL) {
		return true; // Both are NULL, consider them equal
	}
	if (wide_str == NULL || mb_str == NULL) {
		return false; // Only one is NULL, not equal
	}

	char buffer[256];
	int converted = WideCharToMultiByte(CP_UTF8, 0, wide_str, -1,
	                                   buffer, sizeof(buffer), NULL, NULL);
	return converted > 0 && strcmp(buffer, mb_str) == 0;
}

// Convert interface name to interface index using newer API that supports friendly names
static DWORD windows_get_interface_index(const char *ifname) {
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	DWORD dwRetVal = 0;
	ULONG outBufLen = 15000; // Initial buffer size
	ULONG iterations = 0;
	const ULONG MAX_TRIES = 3;

	// Allocate buffer for GetAdaptersAddresses
	do {
		pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
		if (pAddresses == NULL) {
			return 0;
		}

		dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			free(pAddresses);
			pAddresses = NULL;
		} else {
			break;
		}

		iterations++;
	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < MAX_TRIES));

	if (dwRetVal == NO_ERROR) {
		pCurrAddresses = pAddresses;

		while (pCurrAddresses) {
			// Check if adapter has a valid IP address
			PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
			int hasValidIP = 0;

			while (pUnicast != NULL) {
				if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
					struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
					if (sockaddr_ipv4->sin_addr.s_addr != 0 && sockaddr_ipv4->sin_addr.s_addr != INADDR_LOOPBACK) {
						hasValidIP = 1;
						break;
					}
				}
				pUnicast = pUnicast->Next;
			}

			if (hasValidIP) {
				// Try to match: adapter name, friendly name, or description
				if (strcmp(pCurrAddresses->AdapterName, ifname) == 0 ||
					wide_string_matches(pCurrAddresses->FriendlyName, ifname) ||
					wide_string_matches(pCurrAddresses->Description, ifname))
				{
					DWORD index = pCurrAddresses->IfIndex;
					free(pAddresses);
					return index;
				}
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
	}

	if (pAddresses) {
		free(pAddresses);
	}
	return 0;
}

static int windows_set_socket_options(channel_t *channel) {
	// Enable promiscuous mode by setting the socket to receive all packets
	DWORD dwValue = 1;
	DWORD dwSize = sizeof(dwValue);
	DWORD dwBytesReturned = 0;

	// Set socket to receive all packets (promiscuous mode)
	if (WSAIoctl(channel->fd, SIO_RCVALL, &dwValue, dwSize,
	             NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
		sniff_channel_set_error_msg(channel, "WSAIoctl(SIO_RCVALL) failed: %d", WSAGetLastError());
		return -1;
	}

	return 0;
}

// Helper function to get IP address for a specific interface index
static int windows_get_interface_ip(DWORD interface_index, struct in_addr *ip_addr) {
	PIP_ADAPTER_ADDRESSES pAddresses = NULL;
	PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
	DWORD dwRetVal = 0;
	ULONG outBufLen = 15000;
	ULONG iterations = 0;
	const ULONG MAX_TRIES = 3;

	// Allocate buffer for GetAdaptersAddresses
	do {
		pAddresses = (IP_ADAPTER_ADDRESSES *)malloc(outBufLen);
		if (pAddresses == NULL) {
			return -1;
		}

		dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);

		if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
			free(pAddresses);
			pAddresses = NULL;
		} else {
			break;
		}

		iterations++;
	} while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < MAX_TRIES));

	if (dwRetVal == NO_ERROR) {
		pCurrAddresses = pAddresses;

		while (pCurrAddresses) {
			if (pCurrAddresses->IfIndex == interface_index) {
				PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;

				while (pUnicast != NULL) {
					if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
						struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
						if (sockaddr_ipv4->sin_addr.s_addr != 0 && sockaddr_ipv4->sin_addr.s_addr != INADDR_LOOPBACK) {
							*ip_addr = sockaddr_ipv4->sin_addr;
							free(pAddresses);
							return 0;
						}
					}
					pUnicast = pUnicast->Next;
				}
			}
			pCurrAddresses = pCurrAddresses->Next;
		}
	}

	if (pAddresses) {
		free(pAddresses);
	}
	return -1;
}

static int windows_set_interface(channel_t *channel, const char *ifname) {
	// For Windows raw sockets, we need to bind to a specific interface
	// SIO_RCVALL requires binding to an actual interface IP, not INADDR_ANY

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 0;

	// First, get the interface index using the existing function
	DWORD interface_index = windows_get_interface_index(ifname);
	if (interface_index == 0) {
		sniff_channel_set_error_msg(channel, "Interface '%s' not found", ifname);
		return -1;
	}

	// Get the IP address for this interface
	if (windows_get_interface_ip(interface_index, &addr.sin_addr) != 0) {
		sniff_channel_set_error_msg(channel, "Could not get IP address for interface '%s'", ifname);
		return -1;
	}

	if (bind(channel->fd, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
		sniff_channel_set_error_msg(channel, "bind() failed: %d", WSAGetLastError());
		return -1;
	}

	free(channel->ifname);
#ifdef _MSC_VER
	channel->ifname = _strdup(ifname);
#else
	channel->ifname = strdup(ifname);
#endif
	if (channel->ifname == NULL)
		return -1;

	return 0;
}

static int windows_set_immediate(channel_t *channel, int on) {
	// On Windows, raw sockets are typically immediate by default
	// This is mainly for compatibility with the platform abstraction
	UNUSED(channel);
	UNUSED(on);
	return 0;
}

static int windows_set_promisc(channel_t *channel, const char *ifname, int on) {
	// Promiscuous mode on Windows requires administrator privileges
	// and is handled by the SIO_RCVALL ioctl in windows_set_socket_options
	channel->opts.promisc = on;
	UNUSED(ifname);
	return 0;
}

static int windows_set_nonblock(channel_t *channel, int on) {
	u_long mode = on ? 1 : 0;
	if (ioctlsocket(channel->fd, FIONBIO, &mode) == SOCKET_ERROR) {
		sniff_channel_set_error_msg(channel, "ioctlsocket(FIONBIO) failed: %d", WSAGetLastError());
		return -1;
	}
	return 0;
}

static int windows_set_buffersize(channel_t *channel, size_t size) {
	int opt_size = (int)size;

	// Set receive buffer size
	if (setsockopt(channel->fd, SOL_SOCKET, SO_RCVBUF,
	               (char *)&opt_size, sizeof(opt_size)) == SOCKET_ERROR) {
		sniff_channel_set_error_msg(channel, "setsockopt(SO_RCVBUF) failed: %d", WSAGetLastError());
		return -1;
	}

	// Allocate our internal buffer
	free(channel->buffer);
	channel->buffer = malloc(size);
	if (channel->buffer == NULL) {
		sniff_channel_set_error_msg(channel, "Failed to allocate buffer");
		return -1;
	}
	channel->buffer_size = size;

	return 0;
}

// Main interface functions
channel_t *sniff_open(const char *ifname, int promisc, size_t buffer_size) {
	channel_t *channel;

	if (windows_init_winsock() < 0) {
		return NULL;
	}

	channel = sniff_alloc_channel();
	if (channel == NULL)
		return NULL;

	// Create raw socket for IPv4
	channel->fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (channel->fd == INVALID_FD) {
		sniff_channel_set_error_msg(channel, "socket(SOCK_RAW) failed: %d. Administrator privileges required.", WSAGetLastError());
		goto error;
	}

	if (windows_set_interface(channel, ifname) < 0)
		goto error;

	// Set buffer size (keep going if it fails)
	// Ensure we have a minimum buffer size for Windows raw sockets
	if (buffer_size == 0) {
		buffer_size = 65536; // 64KB default
	}

	if (windows_set_buffersize(channel, buffer_size) < 0)
		goto error;

	if (windows_set_immediate(channel, 1) < 0)
		goto error;

	// Set promiscuous mode (keep going if it fails)
	windows_set_promisc(channel, ifname, promisc);

	// Configure socket for promiscuous mode
	if (windows_set_socket_options(channel) < 0)
		goto error;

	return channel;

error:
	LOG_ERROR("%s", channel->errmsg);
	sniff_close(channel);
	return NULL;
}

void sniff_close(channel_t *channel) {
	sniff_free_channel(channel);
}

int sniff_setnonblock(channel_t *channel, int nonblock) {
	if (channel == NULL || channel->fd == INVALID_FD)
		return -1;

	return windows_set_nonblock(channel, nonblock);
}

int sniff_readloop(channel_t *channel, long timeout, const config_t *config) {
	if (channel == NULL || channel->fd == INVALID_FD)
		return -1;

	uint8_t *begin, *end, *current;
	struct timeval tv;
	fd_set readfds;
	int bytes_read;
	time_t time_start = time(NULL);
	time_t time_elapsed;

	while (1) {
		FD_ZERO(&readfds);
		FD_SET(channel->fd, &readfds);

		tv.tv_sec = 0;
		tv.tv_usec = 50000; // 50ms timeout for select

		int select_result = select(0, &readfds, NULL, NULL, &tv);
		if (select_result == SOCKET_ERROR) {
			sniff_channel_set_error_msg(channel, "select() failed: %d", WSAGetLastError());
			return -1;
		} else if (select_result > 0 && FD_ISSET(channel->fd, &readfds)) {
			bytes_read = recv(channel->fd, (char *)channel->buffer, (int)channel->buffer_size, 0);
			if (bytes_read == SOCKET_ERROR) {
				int error = WSAGetLastError();
				// If non-blocking and no data, just continue
				if (error != WSAEWOULDBLOCK) {
					sniff_channel_set_error_msg(channel, "recv() failed: %d", error);
					return -1;
				}
			} else if (bytes_read > 0) {
				begin = channel->buffer;
				end = channel->buffer + bytes_read;

				// loop through each snapshot in the chunk
				while (begin < end) {
					current = begin; // Point to the start of the received buffer because it's not encapsulated.

					// Apply BPF filter if set
					if (sniff_channel_apply_bpf_filter(channel, current, bytes_read)) {
						// On Windows, raw sockets receive IP packets without Ethernet headers, hence we
						// pass ETHERTYPE_IP to directly process the buffer as an IP packet
						sniff_packet_fromwire(current, bytes_read, ETHERTYPE_IP, config);
					}

					begin += bytes_read;
				}
			}
		}

		time_elapsed = time(NULL) - time_start;
		if (timeout > 0 && time_elapsed >= timeout) {
			return 0;
		}

		Sleep(1); // Small delay to prevent busy waiting
	}

	return -1;
}
