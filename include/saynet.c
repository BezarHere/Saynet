#include "saynet.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32")

#define EOK 0
#define ASSERT_CODE_RET(code) if ((code) != EOK) return code

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

static int _ConnectionProtocolToNative(NetConnectionProtocol proto);
static int _ConnectionProtocolToNativeIP(NetConnectionProtocol proto);

static int _InitSocket(NetSocket *pSocket, const NetConnectionParams *params);

static int _ReportError(int code, const char *format, ...);
static void _PutColor(FILE *fp, ConsoleColor color);

SAYNET_API errno_t NetStartServer(NetServer *server, const NetConnectionParams *params) {
	int result_code = 0;

	result_code = _InitSocket(&server->socket, params);
	ASSERT_CODE_RET(result_code);



}

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

int _InitSocket(NetSocket *pSocket, const NetConnectionParams *params) {
	*pSocket = socket(
		AF_UNSPEC,
		_ConnectionProtocolToNative(params->connection_protocol),
		_ConnectionProtocolToNativeIP(params->connection_protocol)
	);

	if (*socket == INVALID_SOCKET)
	{
		return _ReportError(WSAGetLastError(), "Failed to create a socket");
	}

	return EOK;
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

