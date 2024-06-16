#include "saynet.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include <winsock2.h>
#include <ws2tcpip.h>

// #pragma comment(lib, "Ws2_32.lib")

#define EOK 0
#define ASSERT_CODE_RET(code) if ((code) != EOK) return code

#define ASSERT_CLIENT_CREATION(code) if ((code) != EOK) \
{return code; _AbortClient(client, "creation failure");}

#define ASSERT_SERVER_CREATION(code) if ((code) != EOK) \
{return code;} // TODO: implement a server abort function

#define VERBOSE(...) printf(__VA_ARGS__)


#pragma region(defines)

enum
{
	eSocketTCP = SOCK_STREAM,
	eSocketUDB = SOCK_DGRAM,
};

enum
{
	DefaultRecvBufferSz = 0x10000,
	MaxInactivityHits = 2500,
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

typedef struct NetInternalData
{
	size_t recv_buffer_sz;
	uint8_t *recv_buffer;

	NetConnectionParams connection_params;
} NetInternalData;

typedef int (*CallUseAddressProc)(SOCKET, const SOCKADDR *, int);

static WSADATA g_wsa;

static inline int _StartNetService();
static inline int _StopNetService();

static inline errno_t _PollServerUDP(NetServer *server);
static inline errno_t _PollServerTCP(NetServer *server);

static inline int _ConnectionProtocolToNative(NetConnectionProtocol proto);
static inline int _ConnectionProtocolToNativeIP(NetConnectionProtocol proto);
static inline short _AddressTypeToNative(NetAddressType type);
static inline NetAddressType _NativeToAddressType(short type);

static inline int _CallUseAddress(NetSocket socket, const NetConnectionParams *params,
																	CallUseAddressProc proc, const char *context);

static inline int _CreateSocket(NetSocket *pSocket, const NetConnectionParams *params);
static inline int _BindSocket(NetSocket socket, const NetConnectionParams *params);
static inline int _SocketToListen(NetSocket socket);
static inline int _MarkSocketNonBlocking(NetSocket socket);

static inline int _InitSocket(NetSocket *pSocket, const NetConnectionParams *params);

static inline int _ConnectSocket(NetSocket socket, const NetConnectionParams *params);
static inline int _SocketAcceptConn(NetSocket socket, NetClientID *client_id, bool *found);

static inline int _GetSocketAddr(NetSocket socket, NetAddressBuffer *address_out);

// size is in/out
static inline int _RecvFromSocket(NetSocket socket, uint8_t *data, int *size);
static inline int _RecvAnyUDP(NetSocket socket, uint8_t *data, int *size,
															NetAddressType addr_type, NetAddressBuffer *out_address);

// sets the size for the recv and send buffers
static inline int _SetInternalBufferSizes(NetSocket socket, int new_size);
// sets the max msg size, Has no meaning for stream oriented sockets
static inline int _SetMaxMessageSize(NetSocket socket, int new_size);

static inline int _ReportError(int code, const char *format, ...);
static inline void _PutColor(FILE *fp, ConsoleColor color);

static inline NetInternalData *_CreateInternalData();
static inline void _DestroyInternalData(NetInternalData *ptr);

static inline void _CloseClientID(const NetClientID *client_id);
static inline void _CloseSocket(NetSocket socket);

static inline void _AbortClient(NetClient *client, const char *reason);

static inline NetClientIDListNode *_CreateClientIDNode(const NetClientID *client_id);
static inline void _FreeClientIDNode(NetClientIDListNode *node);


// removes it from the linked list and returns it
// returns null if no match can be found
static inline NetClientIDListNode *_ExtractNodeWithClientID(NetClientIDListNode **p_first,
																														const NetClientID *client_id);

// returns the node
static inline NetClientIDListNode *_AppendClientIDNode(NetClientIDListNode **p_first,
																											 NetClientIDListNode *node);

static inline bool _IsSocketDisconnectionError(int error_code);

static inline void *memclear(void *mem, size_t size) {
	return memset(mem, 0, size);
}

#pragma endregion

#pragma region(lib funcs)

errno_t NetOpenClient(NetClient *client, const NetConnectionParams *params) {
	int result_code = 0;

	client->socket = INVALID_SOCKET;

	_DestroyInternalData(client->_handle);
	client->_handle = _CreateInternalData();
	client->_handle->connection_params = *params;

	result_code = _StartNetService();
	ASSERT_CLIENT_CREATION(result_code);

	result_code = _CreateSocket(&client->socket, params);
	ASSERT_CLIENT_CREATION(result_code);

	if (params->connection_protocol == eNConnectProto_TCP)
	{
		result_code = _ConnectSocket(client->socket, params);
		ASSERT_CLIENT_CREATION(result_code);
	}

	return result_code;
}

errno_t NetOpenServer(NetServer *server, const NetConnectionParams *params) {
	int result_code = 0;

	server->socket = INVALID_SOCKET;

	_DestroyInternalData(server->_handle);
	server->_handle = _CreateInternalData();
	server->_handle->connection_params = *params;

	result_code = _StartNetService();
	ASSERT_SERVER_CREATION(result_code);

	result_code = _InitSocket(&server->socket, params);
	ASSERT_SERVER_CREATION(result_code);

	if (params->connection_protocol == eNConnectProto_TCP)
	{
		result_code = _SocketToListen(server->socket);
		ASSERT_SERVER_CREATION(result_code);
	}

	NetAddressBuffer buffer = {0};

	_GetSocketAddr(server->socket, &buffer);

	printf("server %llu hosted at %s\n", server->socket, buffer);

	return result_code;
}

errno_t NetCloseClient(NetClient *client) {
	_DestroyInternalData(client->_handle);
	client->_handle = NULL;

	_CloseSocket(client->socket);
	client->socket = INVALID_SOCKET;

	return _StopNetService();
}

errno_t NetCloseServer(NetServer *server) {
	_DestroyInternalData(server->_handle);

	{
		NetClientIDListNode *node = server->p_client_ids;

		while (node)
		{
			_CloseClientID(&node->client_id);

			NetClientIDListNode *next = node->_next;

			_FreeClientIDNode(node);

			node = next;
		}

	}

	return _StopNetService();
}

errno_t NetPollClient(NetClient *client) {
	return EFAULT;
}

errno_t NetPollServer(NetServer *server) {
	if (server->socket == INVALID_SOCKET || !NetIsServerValid(server))
	{
		return EINVAL;
	}

	// not dealing with overflows in casts (int <-> size_t)
	if (server->_handle->recv_buffer_sz >= INT32_MAX)
	{
		return _ReportError(
			E2BIG,

			"server receive buffer is too big, buffer size is %llu bytes, max size is %d bytes",
			server->_handle->recv_buffer_sz, INT32_MAX
		);
	}

	if (server->_handle->connection_params.connection_protocol != eNConnectProto_TCP)
	{
		return _PollServerUDP(server);
	}

	return _PollServerTCP(server);
}

errno_t NetClientSend(NetClient *client, const void *data, size_t *size) {
	int result = send(client->socket, data, *size, 0);

	if (result == SOCKET_ERROR)
	{
		const int error = WSAGetLastError();
		const size_t original_size = *size;

		*size = 0;

		if (_IsSocketDisconnectionError(error))
		{
			_AbortClient(client, "server disconnected");
		}

		return _ReportError(
			error,

			"client failed to send buffer %p, length %llu bytes in socket %llu",
			data, *size, client->socket
		);
	}

	return EOK;
}

errno_t NetServerKickCLient(NetServer *server, const NetClientID *client_id, const char *reason) {

	NetClientIDListNode *node = _ExtractNodeWithClientID(&server->p_client_ids, client_id);

	if (node == NULL)
	{
		return _ReportError(
			ENOENT,

			"No client has the id {socket=%llu, address=\"%.*s\"}",
			client_id->socket,
			ARRAYSIZE(client_id->address),
			client_id->address
		);
	}

	_CloseClientID(client_id);

	_FreeClientIDNode(node);

	VERBOSE(
		"removed client id {socket=%llu, address=\"%.*s\"}, reason=%s",
		client_id->socket,
		ARRAYSIZE(client_id->address),
		client_id->address,
		reason
	);

	return EOK;
}

#pragma endregion

#pragma region(utility)

inline int _StartNetService() {
	int result = WSAStartup(MAKEWORD(2, 2), &g_wsa);

	if (result != EOK)
	{
		return _ReportError(
			WSAGetLastError(),

			"wsa startup failed, net service can't be run"
		);
	}

	return EOK;
}

inline int _StopNetService() {
	int result = WSACleanup();

	if (result != EOK)
	{
		return _ReportError(
			WSAGetLastError(),

			"wsa cleanup failed, what did you do for this? this shouldn't happen normally"
		);
	}

	return EOK;
}

inline errno_t _PollServerUDP(NetServer *server) {
	while (true)
	{
		NetAddressBuffer address_buffer = {0};

		int size = (int)server->_handle->recv_buffer_sz;

		int result_code = _RecvAnyUDP(
			server->socket,

			server->_handle->recv_buffer,
			&size,

			server->_handle->connection_params.address_type,
			&address_buffer
		);

		// server's socket has shutdown/closed prior to recv
		if (size == 0)
		{
			break;
		}

		if (result_code != EOK)
		{
			// unrecoverable error, stop receiving
			if (size == -2)
			{
				_AbortServer(server, "hard error");
				break;
			}

			// _RecvAnyUDP should have reported something, skip to next iteration
			continue;
		}

	}

	return EOK;
}

inline errno_t _PollServerTCP(NetServer *server) {

	while (true)
	{
		bool found = false;
		NetClientID client_id = {0};

		int result = _SocketAcceptConn(server->socket, &client_id, &found);

		if (result != EOK || !found)
		{
			break;
		}

		if (server->proc_client_joined)
		{
			int result = server->proc_client_joined(&client_id);

			// user returned an error code while processing the new client, kick him
			if (result)
			{
				_CloseClientID(&client_id);
				VERBOSE(
					"kicked client {socket=%llu, address=%.*s}, server code=%d",
					client_id.socket,

					ARRAYSIZE(client_id.address),
					client_id.address,

					result
				);
				continue;
			}
		}

		NetClientIDListNode *node = _AppendClientIDNode(
			&server->p_client_ids,
			_CreateClientIDNode(&client_id)
		);

		VERBOSE(
			"connected: %llu, %.*s\n",
			client_id.socket,

			ARRAYSIZE(client_id.address),
			client_id.address
		);
	}

	NetClientIDListNode *current_node = server->p_client_ids;

	while (current_node != NULL)
	{
		NetClientIDListNode *const node = current_node;
		current_node = current_node->_next;

		int size = (int)server->_handle->recv_buffer_sz;

		int err_code = _RecvFromSocket(node->client_id.socket, server->_handle->recv_buffer, &size);

		// socket didn't send anything (or atleast we didn't receive anything from it)
		if (size < 0)
		{
			node->inactivity_hits++;

			if (node->inactivity_hits >= MaxInactivityHits || size == -2)
			{
				NetServerKickCLient(server, &node->client_id, "inactivity");
			}

			continue;
		}

		node->inactivity_hits = 0;


		if (size > 0 && server->proc_client_recv)
		{
			NetPacketData packet;

			packet.data = server->_handle->recv_buffer;
			packet.size = size;

			server->proc_client_recv(
				&node->client_id,
				packet
			);
		}
	}

	return EOK;
}

int _ConnectionProtocolToNative(NetConnectionProtocol proto) {
	switch (proto)
	{
	case eNConnectProto_TCP:
		return SOCK_STREAM;
	case eNConnectProto_UDP:
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
	case eNConnectProto_UDP:
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

inline NetAddressType _NativeToAddressType(short type) {
	switch (type)
	{
	case AF_INET:
		return eNAddrType_IP4;
	case AF_INET6:
		return eNAddrType_IP6;

	default:
		// TODO: report an error?
		return eNAddrType_IP4;
	}
}

inline int _CallUseAddress(NetSocket socket, const NetConnectionParams *params,
													 const CallUseAddressProc proc, const char *context) {
	enum
	{
		INetPToN_Success = 1
	};
	const short native_addr_type = _AddressTypeToNative(params->address_type);
	const NetPort net_port = htons(params->port);

	const bool any_address = (params->address[0] == 0);

	int result_code = -1;

	if (params->address_type == eNAddrType_IP4)
	{
		struct sockaddr_in address = {0};
		address.sin_family = native_addr_type;
		address.sin_port = net_port;

		if (any_address)
		{
			address.sin_addr = (struct in_addr){0};
			result_code = INetPToN_Success;
		}
		else
		{
			result_code = inet_pton(native_addr_type, params->address, &address.sin_addr);
		}

		if (result_code != INetPToN_Success)
		{
			result_code = WSAGetLastError();
			return _ReportError(
				result_code,

				"%s: inet_pton(%d, \"%.*s\", %p) failed",
				context,

				native_addr_type,

				strnlen(params->address, ARRAYSIZE(params->address)),
				params->address,

				&address.sin_addr
			);
		}

		result_code = proc(socket, (SOCKADDR *)&address, sizeof(address));
	}
	else if (params->address_type == eNAddrType_IP6)
	{
		struct sockaddr_in6 address6 = {0};
		address6.sin6_family = native_addr_type;
		address6.sin6_port = net_port;

		if (any_address)
		{
			address6.sin6_addr = (struct in6_addr){0};
			result_code = INetPToN_Success;
		}
		else
		{
			result_code = inet_pton(native_addr_type, params->address, &address6.sin6_addr);
		}

		if (result_code != INetPToN_Success)
		{
			result_code = WSAGetLastError();
			return _ReportError(
				result_code,

				"%s: inet_pton(%d, \"%.*s\", %p) failed",
				context,

				native_addr_type,

				strnlen(params->address, ARRAYSIZE(params->address)),
				params->address,

				&address6.sin6_addr
			);
		}

		result_code = proc(socket, (SOCKADDR *)&address6, sizeof(address6));
	}

	if (result_code != EOK)
	{
		result_code = WSAGetLastError();
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

int _CreateSocket(NetSocket *pSocket, const NetConnectionParams *params) {
	*pSocket = socket(
		_AddressTypeToNative(params->address_type),
		_ConnectionProtocolToNative(params->connection_protocol),
		IPPROTO_UDP
		// _ConnectionProtocolToNativeIP(params->connection_protocol)
	);

	if (*pSocket == INVALID_SOCKET)
	{
		return _ReportError(WSAGetLastError(), "Failed to create a socket");
	}

	// FIXME: make this configurable by the user
	_SetInternalBufferSizes(*pSocket, DefaultRecvBufferSz);
	_SetMaxMessageSize(*pSocket, DefaultRecvBufferSz + 256);

	return EOK;
}

int _BindSocket(const NetSocket socket, const NetConnectionParams *params) {
	return _CallUseAddress(socket, params, bind, "while binding socket");
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

	// yes, i meant to cast the const away; check ioctlsocket declaration
	int result_code = ioctlsocket(socket, FIONBIO, (u_long *)&mode);

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

inline int _ConnectSocket(NetSocket socket, const NetConnectionParams *params) {
	return _CallUseAddress(socket, params, connect, "while connecting socket");
}

inline int _SocketAcceptConn(NetSocket socket, NetClientID *client_id, bool *found) {
	// TODO: change the address type between sockaddr_in & sockaddr_in6 depending on the server's address type
	SOCKADDR addr = {0};
	int addr_len = sizeof(addr);

	const NetSocket new_socket = accept(socket, &addr, &addr_len);

	if (new_socket == INVALID_SOCKET)
	{
		*found = false;

		int error = WSAGetLastError();
		if (error == WSAEWOULDBLOCK)
		{
			return EOK;
		}

		return _ReportError(
			error,

			"something happened while accepting connections to socket %llu",
			socket
		);
	}

	*found = true;



	client_id->socket = new_socket;
	client_id->address_type = _NativeToAddressType(addr.sa_family);

	// clear address representation
	memclear(client_id->address, ARRAYSIZE(client_id->address));

	inet_ntop(
		addr.sa_family,
		&addr,
		client_id->address,
		ARRAYSIZE(client_id->address)
	);

	// to make sure, set the last char to a null termination
	client_id->address[ARRAYSIZE(client_id->address) - 1] = 0;

	VERBOSE("accepted address %s", client_id->address);

	return EOK;
}

inline int _GetSocketAddr(NetSocket socket, NetAddressBuffer *address_out) {
	memclear(address_out, ARRAYSIZE(*address_out));

	SOCKADDR addr = {0};
	int length = sizeof(addr);

	int result = getsockname(socket, &addr, &length);

	if (result != EOK)
	{
		return _ReportError(
			WSAGetLastError(),

			"failed to get the socket address of socket %llu",
			socket
		);
	}

	const int address_family = AF_INET;

	inet_ntop(address_family, &addr, *address_out, ARRAYSIZE(*address_out));

	// if (result != 1)
	// {
	// 	return _ReportError(
	// 		WSAGetLastError(),

	// 		"while getting socket address: inet_ntop(%d, %p, %p, %llu) failed",
	// 		address_family,
	// 		&addr,
	// 		*address_out,
	// 		ARRAYSIZE(*address_out)
	// 	);
	// }

	return EOK;
}

inline int _RecvFromSocket(NetSocket socket, uint8_t *data, int *size) {
	const int result = recv(socket, (char *)data, *size, 0);

	if (result < 0)
	{
		const int error = WSAGetLastError();
		const int original_size = *size;

		// there is simply no data to receive
		if (error == WSAEWOULDBLOCK)
		{
			*size = 0;
			return EOK;
		}

		if (_IsSocketDisconnectionError(error))
		{
			*size = -2;
		}

		return _ReportError(
			error,

			"failed to receive data to buffer [%p, len=%d] from socket %llu",
			data,
			original_size,
			socket
		);
	}

	if (result == 0)
	{
		*size = -1;
	}
	else
	{
		*size = result;
	}

	return EOK;
}

inline int _RecvAnyUDP(NetSocket socket, uint8_t *data, int *size,
											 NetAddressType addr_type, NetAddressBuffer *out_address) {
	const int native_addr_family = _AddressTypeToNative(addr_type);
	const int original_size = *size;

	memclear(*out_address, ARRAYSIZE(*out_address));

	if (addr_type == eNAddrType_IP4)
	{
		SOCKADDR_IN addr = {0};
		int len = sizeof(addr);

		int result = recvfrom(socket, (char *)data, *size, 0, (SOCKADDR *)&addr, &len);

		if (result < 0)
		{
			const int error = WSAGetLastError();

			// unrecoverable error
			if (_IsSocketDisconnectionError(error))
			{
				*size = -2;
			}
			// no more stuff to receive (socket tried to block to get more)
			else if (error == WSAEWOULDBLOCK)
			{
				*size = 0;
			}
			// average error
			else
			{
				*size = -1;
			}

			return _ReportError(
				error,

				"failed to receive data to buffer [%p, len=%d] from socket %llu (UDP)",

				data,
				original_size,
				socket
			);
		}


		*size = result;


		inet_ntop(native_addr_family, &addr, *out_address, ARRAYSIZE(*out_address));
	}

	else if (addr_type == eNAddrType_IP6)
	{
		SOCKADDR_IN6 addr = {0};
		int len = sizeof(addr);

		int result = recvfrom(socket, (char *)data, *size, 0, (SOCKADDR *)&addr, &len);

		if (result < 0)
		{
			const int error = WSAGetLastError();

			if (_IsSocketDisconnectionError(error))
			{
				*size = -2;
			}
			else
			{
				*size = -1;
			}

			return _ReportError(
				error,

				"failed to receive data to buffer [%p, len=%d] from socket %llu (UDP)",

				data,
				original_size,
				socket
			);
		}


		*size = result;


		inet_ntop(native_addr_family, &addr, *out_address, ARRAYSIZE(*out_address));
	}

	(*out_address)[ARRAYSIZE(*out_address) - 1] = 0;

	return EOK;
}

inline int _SetInternalBufferSizes(NetSocket socket, const int new_size) {
	int result_code = 0;

	result_code = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (const char *)&new_size, sizeof(new_size));
	if (result_code == SOCKET_ERROR)
	{
		return _ReportError(
			WSAGetLastError(),

			"failed to set the SO_RCVBUF for the socket %llu to %d",
			socket,
			new_size
		);
	}

	result_code = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (const char *)&new_size, sizeof(new_size));
	if (result_code == SOCKET_ERROR)
	{
		return _ReportError(
			WSAGetLastError(),

			"failed to set the SO_SNDBUF for the socket %llu to %d",
			socket,
			new_size
		);
	}


	return EOK;
}

inline int _SetMaxMessageSize(NetSocket socket, const int new_size) {

	int result_code = setsockopt(
		socket,
		SOL_SOCKET,
		SO_MAX_MSG_SIZE,
		(const char *)&new_size,
		sizeof(new_size)
	);

	if (result_code == SOCKET_ERROR)
	{
		return _ReportError(
			WSAGetLastError(),

			"failed to set the SO_MAX_MSG_SIZE for the socket %llu to %d",
			socket,
			new_size
		);
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

inline NetInternalData *_CreateInternalData() {
	NetInternalData *data = malloc(sizeof(*data));
	if (data == NULL)
	{
		_ReportError(ENOMEM, "failed to allocate internal data");
		exit(ENOMEM);
		return NULL;
	}

	data->recv_buffer_sz = DefaultRecvBufferSz;
	data->recv_buffer = malloc(data->recv_buffer_sz);

	if (data->recv_buffer == NULL)
	{
		_ReportError(ENOMEM, "failed to allocate recv buffer: size=%llu bytes", data->recv_buffer_sz);
		exit(ENOMEM);
		return NULL;
	}

	memclear(data->recv_buffer, data->recv_buffer_sz);

	return data;
}

inline void _DestroyInternalData(NetInternalData *ptr) {
	if (ptr == NULL)
	{
		return;
	}

	free(ptr->recv_buffer);
	free(ptr);
}

inline void _CloseClientID(const NetClientID *client_id) {
	_CloseSocket(client_id->socket);
	// client_id->socket = INVALID_SOCKET;
}

inline void _CloseSocket(NetSocket socket) {
	shutdown(socket, SD_BOTH);
	closesocket(socket);
}

inline void _AbortClient(NetClient *client, const char *reason) {
	// TODO: colorize/use colorized print function to something like YELLOW
	_ReportError(E_ABORT, "client: connection aborted: reason=\"%s\"\n", reason);
	NetCloseClient(client);
}

inline NetClientIDListNode *_CreateClientIDNode(const NetClientID *client_id) {
	NetClientIDListNode *node = malloc(sizeof(*node));

	if (node == NULL)
	{
		exit(
			_ReportError(
				ENOMEM,

				"failed to allocate a client id list node for client id: socket=%llu address=\"%.*s\"",

				client_id->socket,

				ARRAYSIZE(client_id->address),
				client_id->address
			)
		);
		return NULL;
	}

	node->client_id = *client_id;
	node->inactivity_hits = 0;
	node->_next = NULL;

	return node;
}

inline void _FreeClientIDNode(NetClientIDListNode *node) {
	free(node);
}

inline NetClientIDListNode *_ExtractNodeWithClientID(NetClientIDListNode **p_first, const NetClientID *client_id) {
	NetClientIDListNode *last = NULL;
	NetClientIDListNode *node = *p_first;

	while (node != NULL)
	{
		if (node->client_id.socket == client_id->socket)
		{
			if (last)
			{
				// skip the node
				last->_next = node->_next;
			}
			else
			{
				// last can only equal null if we are at the first node
				// thus, override first node to be the second node
				*p_first = node->_next;
			}


			return node;
		}

		last = node;
		node = node->_next;
	}

	return NULL;
}

inline NetClientIDListNode *_AppendClientIDNode(NetClientIDListNode **p_first,
																								NetClientIDListNode *node) {

	node->_next = NULL;

	if (*p_first == NULL)
	{
		*p_first = node;
		return node;
	}

	NetClientIDListNode *current_node = *p_first;

	while (current_node)
	{
		if (current_node->_next == NULL)
		{
			current_node->_next = node;
			break;
		}

		current_node = current_node->_next;
	}

	return node;
}

inline bool _IsSocketDisconnectionError(int error_code) {
	return error_code == WSAESHUTDOWN || error_code == WSAECONNRESET || error_code == WSAECONNABORTED;
}

#pragma endregion
