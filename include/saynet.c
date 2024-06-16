#include "saynet.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32")

#define EOK 0
#define ASSERT_CODE_RET(code) if ((code) != EOK) return code


#pragma region(defines)

enum
{
	eSocketTCP = SOCK_STREAM,
	eSocketUDB = SOCK_DGRAM,
};

typedef enum ConsoleColor
{
	eFGClr_Clear = 0,
	// eFGClr_Black = 30,
	eFGClr_Red = 31,
	eFGClr_Green = 32,
	eFGClr_Yellow = 33,
	eFGClr_Blue = 34,
} ConsoleColor;

static inline int _ConnectionProtocolToNative(NetConnectionProtocol proto);
static inline int _ConnectionProtocolToNativeIP(NetConnectionProtocol proto);
static inline short _AddressTypeToNative(NetAddressType type);

static inline int _CreateSocket(NetSocket *pSocket, const NetConnectionParams *params);
static inline int _BindSocket(NetSocket socket, const NetConnectionParams *params);
static inline int _SocketToListen(NetSocket socket);
static inline int _MarkSocketNonBlocking(NetSocket socket);

static inline int _InitSocket(NetSocket *pSocket, const NetConnectionParams *params);

static inline int _ReportError(int code, const char *format, ...);
static inline void _PutColor(FILE *fp, ConsoleColor color);

#pragma endregion

#pragma region(lib funcs)

errno_t NetOpenClient(NetClient *client, const NetConnectionParams *params) {
	int result_code = 0;

	result_code = _InitSocket(&client->socket, params);
	ASSERT_CODE_RET(result_code);

	return result_code;
}

errno_t NetOpenServer(NetServer *server, const NetConnectionParams *params) {
	int result_code = 0;

	result_code = _InitSocket(&server->socket, params);
	ASSERT_CODE_RET(result_code);


	result_code = _SocketToListen(server->socket);
	ASSERT_CODE_RET(result_code);

}

errno_t NetCloseClient(NetClient *client, const NetConnectionParams *params) {
	return EFAULT;
}

errno_t NetCloseServer(NetServer *server, const NetConnectionParams *params) {
	return EFAULT;
}

errno_t NetPollClient(const NetClient *client) {
	return EFAULT;
}

errno_t NetPollServer(const NetServer *server) {
	return EFAULT;
}

#pragma endregion

#pragma region(utility)

int _ConnectionProtocolToNative(NetConnectionProtocol proto) {
	switch (proto)
	{
	case eNConnectProto_TCP:
		return SOCK_STREAM;
	case eNConnectProto_UDB:
		return SOCK_DGRAM;

	default:
		return SOCK_DGRAM;
	}
}

int _ConnectionProtocolToNativeIP(NetConnectionProtocol proto) {
	switch (proto)
	{
	case eNConnectProto_TCP:
		return IPPROTO_UDP;
	case eNConnectProto_UDB:
		return IPPROTO_TCP;

	default:
		return IPPROTO_TCP;
	}
}

short _AddressTypeToNative(NetAddressType type) {
	switch (type)
	{
	case eNAddrType_IP4:
		return AF_INET;
	case eNAddrType_IP6:
		return AF_INET6;

	default:
		return 0;
	}
}

int _CreateSocket(NetSocket *pSocket, const NetConnectionParams *params) {
	*pSocket = socket(
		AF_UNSPEC,
		_ConnectionProtocolToNative(params->connection_protocol),
		_ConnectionProtocolToNativeIP(params->connection_protocol)
	);

	if (*pSocket == INVALID_SOCKET)
	{
		return _ReportError(WSAGetLastError(), "Failed to create a socket");
	}

	return EOK;
}

int _BindSocket(const NetSocket socket, const NetConnectionParams *params) {
	const short native_addr_type = _AddressTypeToNative(params->address_type);
	const NetPort net_port = htons(params->port);

	int result_code = -1;

	if (params->address_type == eNAddrType_IP4)
	{
		struct sockaddr_in address = {0};
		address.sin_family = native_addr_type;
		address.sin_port = net_port;

		result_code = inet_pton(native_addr_type, params->address, &address.sin_addr);

		if (result_code != EOK)
		{
			return _ReportError(
				result_code,

				"inet_pton(%d, \"%.*s\", %p) failed",
				native_addr_type,

				strnlen(params->address, ARRAYSIZE(params->address)),
				params->address,

				&address.sin_addr
			);
		}

		result_code = bind(socket, (SOCKADDR *)&address, sizeof(address));
	}
	else if (params->address_type == eNAddrType_IP6)
	{
		struct sockaddr_in6 address6 = {0};
		address6.sin6_family = native_addr_type;
		address6.sin6_port = net_port;

		result_code = inet_pton(native_addr_type, params->address, &address6.sin6_addr);

		if (result_code != EOK)
		{
			return _ReportError(
				result_code,

				"inet_pton(%d, \"%.*s\", %p) failed",
				native_addr_type,

				strnlen(params->address, ARRAYSIZE(params->address)),
				params->address,

				&address6.sin6_addr
			);
		}

		result_code = bind(socket, (SOCKADDR *)&address6, sizeof(address6));
	}

	if (result_code != EOK)
	{
		return _ReportError(
			result_code,

			"failed to bind socket %llu to \"%.*s\"",
			socket,

			strnlen(params->address, ARRAYSIZE(params->address)),
			params->address
		);
	}

	return 0;
}

int _SocketToListen(NetSocket socket) {
	int result_code = listen(socket, SOMAXCONN);

	if (result_code != EOK)
	{
		return _ReportError(
			result_code,

			"failed to make a socket (%llu) listen to connection",
			socket
		);
	}

	return result_code;
}

int _MarkSocketNonBlocking(NetSocket socket) {
	static const u_long mode = 1;
	int result_code = ioctlsocket(socket, FIONBIO, &mode);

	if (result_code != EOK)
	{
		return _ReportError(
			result_code,

			"marking the socket %llu as non-blocking failed",
			socket
		);
	}

	return EOK;
}

int _InitSocket(NetSocket *pSocket, const NetConnectionParams *params) {
	int result_code = 0;

	result_code = _CreateSocket(pSocket, params);
	ASSERT_CODE_RET(result_code);

	result_code = _BindSocket(*pSocket, params);
	ASSERT_CODE_RET(result_code);

	result_code = _MarkSocketNonBlocking(*pSocket);
	ASSERT_CODE_RET(result_code);

	return result_code;
}

/// @returns any value passed in `code`
int _ReportError(int code, const char *format, ...) {

	printf("ERROR[%d]: ", code);
	_PutColor(stdout, eFGClr_Red);

	va_list va_list;
	va_start(va_list, format);
	vprintf(format, va_list);
	va_end(va_list);

	_PutColor(stdout, eFGClr_Clear);
	fputc('\n', stdout);

	return code;
}

void _PutColor(FILE *fp, ConsoleColor color) {
	fprintf(fp, "\033[%dm", color);
}

#pragma endregion
