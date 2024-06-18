#include "saynet.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

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

#define ERROR_ENTRY(name) case name: return (#name) + 1

// skip the 'WSA' part
#define ERROR_ENTRY_WSA(name) case name: return (#name)

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

	MaxAddressListSize = 24
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

typedef struct InAddress
{
	union _InAddress_data
	{
		IN_ADDR ipv4;
		IN6_ADDR ipv6;
	} data;
	int length;
} InAddress;

typedef struct SockInAddress
{
	union _SockInAddress_data
	{
		SOCKADDR_IN addr;
		SOCKADDR_IN6 addr6;
	} data;
	int length;
} SockInAddress;

typedef struct NetInternalData
{
	size_t recv_buffer_sz;
	uint8_t *recv_buffer;

	NetCreateParams connection_params;
} NetInternalData;

typedef struct AddressListNode
{
	NetAddress net_address;
	SockInAddress sock_inaddr;
	InAddress inaddr;
} AddressListNode;

typedef struct AddressList
{
	size_t count;
	AddressListNode data[MaxAddressListSize];
} AddressList;

typedef int (*CallUseAddressProc)(SOCKET, const SOCKADDR *, int);

static WSADATA g_wsa;

static inline int _StartNetService();
static inline int _StopNetService();

static inline errno_t _PollServerUDP(NetServer *server);
static inline errno_t _PollServerTCP(NetServer *server);

static inline int _ConnectionProtocolToNativeST(NetConnectionProtocol proto);
static inline int _ConnectionProtocolToNativeIP(NetConnectionProtocol proto);
static inline short _AddressTypeToNative(NetAddressType type);
static inline NetAddressType _NativeToAddressType(short type);

static inline int _CallUseAddress(NetSocket socket, const NetCreateParams *params,
																	CallUseAddressProc proc, const char *context);

static inline int _CreateSocket(NetSocket *pSocket, const NetCreateParams *params);
static inline int _BindSocket(NetSocket socket, const NetCreateParams *params);
static inline int _SocketToListen(NetSocket socket);
static inline int _MarkSocketNonBlocking(NetSocket socket);

static inline int _InitSocket(NetSocket *pSocket, const NetCreateParams *params);

static inline int _ConnectSocket(NetSocket socket, const NetCreateParams *params);
static inline int _SocketAcceptConn(NetSocket socket, NetClientID *client_id, bool *found);

static inline int _GetSocketAddr(NetSocket socket, NetAddressBuffer *address_out);

// size is in/out
static inline int _RecvFromSocket(NetSocket socket, uint8_t *data, int *size);
static inline int _RecvAnyUDP(NetSocket socket, uint8_t *data, int *size, NetAddress *address);

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

static inline void _AbortServer(NetServer *server, const char *reason);
static inline void _AbortClient(NetClient *client, const char *reason);

static inline NetClientIDListNode *_CreateClientIDNode(const NetClientID *client_id);
static inline void _FreeClientIDNode(NetClientIDListNode *node);

static inline int _ConvertNetAddressToInAddr(const NetAddress *address, InAddress *output);
static inline int _ConvertInAddrToNetAddress(const InAddress *in_addr, NetAddress *output);
static inline int _ConvertNetAddressToSockInAddr(const NetAddress *address, NetPort port,
																								 SockInAddress *output);

static inline int _HostNameToAddressList(NetPort port, NetAddressType address_type,
																				 NetConnectionProtocol conn_protocol,
																				 AddressList *output);

static inline SockInAddress _SockInAddrFromDynamicSockAddr(const SOCKADDR *addr, int length);
static inline InAddress _InAddrFromSockInAddr(const SockInAddress *sock_in_addr);

// removes it from the linked list and returns it
// returns null if no match can be found
static inline NetClientIDListNode *_ExtractNodeWithClientID(NetClientIDListNode **p_first,
																														const NetClientID *client_id);

// returns the node
static inline NetClientIDListNode *_AppendClientIDNode(NetClientIDListNode **p_first,
																											 NetClientIDListNode *node);

static inline bool _IsSocketDisconnectionError(int error_code);

static inline errno_t _GetLastNetError();
static inline const char *_GetErrorName(errno_t error);

static inline void *memclear(void *mem, size_t size) {
	return memset(mem, 0, size);
}

#pragma endregion

#pragma region(lib funcs)

errno_t NetOpenClient(NetClient *client, const NetCreateParams *params) {
	int result_code = 0;

	client->socket = INVALID_SOCKET;

	_DestroyInternalData(client->_internal);
	client->_internal = _CreateInternalData();
	client->_internal->connection_params = *params;

	result_code = _StartNetService();
	ASSERT_CLIENT_CREATION(result_code);


	_HostNameToAddressList(params->port, params->address_type, params->connection_protocol, NULL);

	result_code = _CreateSocket(&client->socket, params);
	ASSERT_CLIENT_CREATION(result_code);

	if (params->connection_protocol == eNConnectProto_TCP)
	{
		result_code = _ConnectSocket(client->socket, params);
		ASSERT_CLIENT_CREATION(result_code);
	}
	else
	{
		result_code = _BindSocket(client->socket, params);
		ASSERT_CLIENT_CREATION(result_code);
	}

	return result_code;
}

errno_t NetOpenServer(NetServer *server, const NetCreateParams *params) {
	int result_code = 0;


	server->socket = INVALID_SOCKET;

	_DestroyInternalData(server->_internal);
	server->_internal = _CreateInternalData();
	server->_internal->connection_params = *params;

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
	_DestroyInternalData(client->_internal);
	client->_internal = NULL;

	_CloseSocket(client->socket);
	client->socket = INVALID_SOCKET;

	return _StopNetService();
}

errno_t NetCloseServer(NetServer *server) {
	_DestroyInternalData(server->_internal);

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
	if (server->_internal->recv_buffer_sz >= INT32_MAX)
	{
		return _ReportError(
			E2BIG,

			"server receive buffer is too big, buffer size is %llu bytes, max size is %d bytes",
			server->_internal->recv_buffer_sz, INT32_MAX
		);
	}

	if (server->_internal->connection_params.connection_protocol != eNConnectProto_TCP)
	{
		return _PollServerUDP(server);
	}

	return _PollServerTCP(server);
}

const NetCreateParams *NetClientGetCreateParams(const NetClient *client) {
	return &client->_internal->connection_params;
}

const NetCreateParams *NetServerGetCreateParams(const NetServer *server) {
	return &server->_internal->connection_params;
}

errno_t NetClientSendToUDP(NetClient *client,
													 const void *data, size_t *size,
													 const NetUserAddress *address) {
	SockInAddress sock_addr = {0};

	//! FIXME: error-out if the send address is identical to the client's address (INVALID IN UDP)

	const NetPort port = address->port;

	// TODO: check return code
	_ConvertNetAddressToSockInAddr(
		// NOTE: a pointer to a NetUserAddress is identical to a pointer to a NetAddress
		// given that the start of NetUserAddress is just a NetAddress
		(const NetAddress *)address,
		port,
		&sock_addr
	);

	int result_code = sendto(
		client->socket,
		(const char *)data,
		// FIXME: this will overflow! check for overflow later
		(int)*size,
		0,
		(const SOCKADDR *)&sock_addr.data,
		sock_addr.length
	);

	if (result_code <= -1)
	{
		const int error = _GetLastNetError();
		const size_t original_size = *size;

		*size = 0;

		if (_IsSocketDisconnectionError(error))
		{
			_AbortClient(client, "hard error");
		}

		return _ReportError(
			error,

			"client failed to send (UDP) buffer %p, length %llu bytes in socket %llu to \"%s\":%d",
			data, original_size, client->socket, address->name, port
		);
	}

	*size = result_code;

	return result_code;
}

errno_t NetClientSend(NetClient *client, const void *data, size_t *size) {
	// FIXME: this will overflow! check for overflow later
	int result = send(client->socket, data, (int)*size, 0);

	if (result == SOCKET_ERROR)
	{
		const int error = _GetLastNetError();
		const size_t original_size = *size;

		*size = 0;

		if (_IsSocketDisconnectionError(error))
		{
			_AbortClient(client, "server disconnected");
		}

		return _ReportError(
			error,

			"client failed to send buffer %p, length %llu bytes in socket %llu",
			data, original_size, client->socket
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
		(int)ARRAYSIZE(client_id->address),
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
			_GetLastNetError(),

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
			_GetLastNetError(),

			"wsa cleanup failed, what did you do for this? this shouldn't happen normally"
		);
	}

	return EOK;
}

inline errno_t _PollServerUDP(NetServer *server) {
	NetAddress address = {0};
	address.type = NetServerGetCreateParams(server)->address_type;

	while (true)
	{
		int size = (int)server->_internal->recv_buffer_sz;

		int result_code = _RecvAnyUDP(
			server->socket,

			server->_internal->recv_buffer,
			&size,

			&address
		);

		// server's socket has shutdown/closed prior to recv
		if (size == 0)
		{
			break;
		}

		VERBOSE("received %d bytes on udp", size);

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

		// process data

		if (server->proc_udp_recv)
		{
			NetPacketData data = {0};

			data.data = server->_internal->recv_buffer;
			data.size = server->_internal->recv_buffer_sz;

			const int callback_recv_result = server->proc_udp_recv(&address, data);

			// nothing todo with this rn
			(void)callback_recv_result;
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

					(int)ARRAYSIZE(client_id.address),
					client_id.address,

					result
				);
				continue;
			}
		}

		// discard return, return is the created node passed in as an argument
		(void)_AppendClientIDNode(
			&server->p_client_ids,
			_CreateClientIDNode(&client_id)
		);

		VERBOSE(
			"connected: %llu, %.*s\n",
			client_id.socket,

			(int)ARRAYSIZE(client_id.address),
			client_id.address
		);
	}

	NetClientIDListNode *current_node = server->p_client_ids;

	while (current_node != NULL)
	{
		NetClientIDListNode *const node = current_node;
		current_node = current_node->_next;

		int size = (int)server->_internal->recv_buffer_sz;

		const int err_code = \
			_RecvFromSocket(node->client_id.socket, server->_internal->recv_buffer, &size);

		// error checking is done by the output parameter 'size'
		(void)err_code;

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

			packet.data = server->_internal->recv_buffer;
			packet.size = size;

			server->proc_client_recv(
				&node->client_id,
				packet
			);
		}
	}

	return EOK;
}

int _ConnectionProtocolToNativeST(NetConnectionProtocol proto) {
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
		return IPPROTO_TCP;
	case eNConnectProto_UDP:
		return IPPROTO_UDP;

	default:
		return IPPROTO_TCP;
	}
}

short _AddressTypeToNative(NetAddressType type) {
	switch (type)
	{
	case eNAddrType_IPv4:
		return AF_INET;
	case eNAddrType_IPv6:
		return AF_INET6;

	default:
		return 0;
	}
}

inline NetAddressType _NativeToAddressType(short type) {
	switch (type)
	{
	case AF_INET:
		return eNAddrType_IPv4;
	case AF_INET6:
		return eNAddrType_IPv6;

	default:
		// TODO: report an error?
		return eNAddrType_IPv4;
	}
}

inline int _CallUseAddress(NetSocket socket, const NetCreateParams *params,
													 const CallUseAddressProc proc, const char *context) {

	NetAddress address = {0};

	address.type = params->address_type;
	memcpy(
		address.name,
		params->address,
		ARRAYSIZE(address.name)
	);

	SockInAddress sock_addr = {0};

	int result_code = -1;

	result_code = _ConvertNetAddressToSockInAddr(&address, htons(params->port), &sock_addr);

	if (result_code != EOK)
	{
		return _ReportError(
			result_code,

			"failed to encode address \"%s\" port %d",
			address.name, params->port
		);
	}

	// rebuild address to be the representation fo the new processed native address
	{
		const InAddress in_address = _InAddrFromSockInAddr(&sock_addr);
		_ConvertInAddrToNetAddress(&in_address, &address);
	}

	result_code = proc(socket, (SOCKADDR *)&sock_addr.data, sock_addr.length);

	if (result_code != EOK)
	{
		result_code = _GetLastNetError();
		return _ReportError(
			result_code,

			"%s: failed; socket=%llu, address=\"%s\", port=%d",
			context,
			socket,
			address.name,
			params->port
		);
	}

	return EOK;
}

int _CreateSocket(NetSocket *pSocket, const NetCreateParams *params) {
	*pSocket = socket(
		_AddressTypeToNative(params->address_type),
		_ConnectionProtocolToNativeST(params->connection_protocol),
		_ConnectionProtocolToNativeIP(params->connection_protocol)
	);

	if (*pSocket == INVALID_SOCKET)
	{
		return _ReportError(_GetLastNetError(), "Failed to create a socket");
	}

	// FIXME: make this configurable by the user
	_SetInternalBufferSizes(*pSocket, DefaultRecvBufferSz);
	_SetMaxMessageSize(*pSocket, DefaultRecvBufferSz + 256);

	return EOK;
}

int _BindSocket(const NetSocket socket, const NetCreateParams *params) {
	return _CallUseAddress(socket, params, bind, "binding socket");
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

int _InitSocket(NetSocket *pSocket, const NetCreateParams *params) {
	int result_code = 0;

	result_code = _CreateSocket(pSocket, params);
	ASSERT_CODE_RET(result_code);

	result_code = _BindSocket(*pSocket, params);
	ASSERT_CODE_RET(result_code);

	result_code = _MarkSocketNonBlocking(*pSocket);
	ASSERT_CODE_RET(result_code);

	return result_code;
}

inline int _ConnectSocket(NetSocket socket, const NetCreateParams *params) {
	return _CallUseAddress(socket, params, connect, "connecting socket");
}

inline int _SocketAcceptConn(NetSocket socket, NetClientID *client_id, bool *found) {
	// TODO: change the address type between sockaddr_in & sockaddr_in6 depending on the server's address type
	SOCKADDR addr = {0};
	int addr_len = sizeof(addr);

	const NetSocket new_socket = accept(socket, &addr, &addr_len);

	if (new_socket == INVALID_SOCKET)
	{
		*found = false;

		int error = _GetLastNetError();
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
			_GetLastNetError(),

			"failed to get the socket address of socket %llu",
			socket
		);
	}

	const int address_family = AF_INET;

	inet_ntop(address_family, &addr, *address_out, ARRAYSIZE(*address_out));

	// if (result != 1)
	// {
	// 	return _ReportError(
	// 		_GetLastNetError(),

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
		const int error = _GetLastNetError();
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

inline int _RecvAnyUDP(NetSocket socket, uint8_t *data, int *size, NetAddress *address) {
	enum { recvfrom_flags = 0 };
	// value of (*size) at the head of the function, prior to any modifications 
	const int original_size = *size;

	memclear(address->name, ARRAYSIZE(address->name));

	SockInAddress sock_in_addr = {0};
	sock_in_addr.length = sizeof(sock_in_addr);

	const int result = recvfrom(
		socket,
		(char *)data,
		original_size,
		recvfrom_flags,
		(SOCKADDR *)&sock_in_addr.data,
		&sock_in_addr.length
	);

	if (result < 0)
	{
		const int error = _GetLastNetError();

		// no data, wsa would block waiting for more data to arrive
		// but we disabled waiting
		if (error == WSAEWOULDBLOCK)
		{
			*size = 0;
			return EOK;
		}

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

			"recvfrom failed and didn't return the any address as buffer [%p, len=%d] from socket %llu (UDP)",

			data,
			original_size,
			socket
		);
	}

	*size = result;

	{
		const InAddress in_address = _InAddrFromSockInAddr(&sock_in_addr);
		// TODO: error checking
		_ConvertInAddrToNetAddress(&in_address, address);
	}

	(address->name)[ARRAYSIZE(address->name) - 1] = 0;

	return EOK;
}

inline int _SetInternalBufferSizes(NetSocket socket, const int new_size) {
	int result_code = 0;

	result_code = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, (const char *)&new_size, sizeof(new_size));
	if (result_code == SOCKET_ERROR)
	{
		return _ReportError(
			_GetLastNetError(),

			"failed to set the SO_RCVBUF for the socket %llu to %d",
			socket,
			new_size
		);
	}

	result_code = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (const char *)&new_size, sizeof(new_size));
	if (result_code == SOCKET_ERROR)
	{
		return _ReportError(
			_GetLastNetError(),

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
			_GetLastNetError(),

			"failed to set the SO_MAX_MSG_SIZE for the socket %llu to %d",
			socket,
			new_size
		);
	}

	return EOK;
}

/// @returns any value passed in `code`
int _ReportError(int code, const char *format, ...) {

	_PutColor(stdout, eFGClr_Red);
	printf("ERR[%s]: ", _GetErrorName(code));

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

inline void _AbortServer(NetServer *server, const char *reason) {
	// TODO: colorize/use colorized print function to something like YELLOW
	_ReportError(E_ABORT, "server: aborted hosting: reason=\"%s\"\n", reason);
	NetCloseServer(server);
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

inline int _ConvertNetAddressToInAddr(const NetAddress *address, InAddress *output) {
	enum
	{
		INetPToN_WSAERRor = -1,
		INetPToN_InvalidAddressFormat = 0,
		INetPToN_Success = 1,
	};

	const int native_addr_type = _AddressTypeToNative(address->type);

	// either the address name starts with null (zero length) or is equal to "*"
	const bool any_addr = (address->name[0] == 0 || strcmp("*", address->name) == 0);


	int inet_pton_result_code = INetPToN_Success;


	//* === === === IPv6 === === ===
	if (address->type == eNAddrType_IPv6)
	{
		output->length = sizeof(output->data.ipv6);

		if (any_addr)
		{
			output->data.ipv6 = (IN6_ADDR)IN6ADDR_ANY_INIT;
			return EOK;
		}

		inet_pton_result_code = inet_pton(native_addr_type, address->name, &output->data.ipv6);
	}

	//* === === === IPv4 === === ===
	else
	{
		output->length = sizeof(output->data.ipv4);

		if (any_addr)
		{
			// IN_ADDR is nested structs & unions
			output->data.ipv4 = (IN_ADDR){{{htonl(INADDR_ANY)}}};
			return EOK;
		}

		inet_pton_result_code = inet_pton(native_addr_type, address->name, &output->data.ipv4);
	}


	if (inet_pton_result_code == INetPToN_InvalidAddressFormat)
	{
		return EBADF;
	}

	if (inet_pton_result_code == INetPToN_WSAERRor)
	{
		return _GetLastNetError();
	}

	return EOK;
}

inline int _ConvertInAddrToNetAddress(const InAddress *in_addr, NetAddress *output) {

	if (in_addr->length == sizeof(IN6_ADDR))
	{
		//* IPv6
		output->type = eNAddrType_IPv6;
	}
	else if (in_addr->length == sizeof(IN_ADDR))
	{
		//* IPv6
		output->type = eNAddrType_IPv4;
	}
	else
	{
		// unsupported, only IPv4 and IPv6
		return EAFNOSUPPORT;
	}

	const char *result = inet_ntop(
		_AddressTypeToNative(output->type),
		&in_addr->data,
		output->name,
		ARRAYSIZE(output->name)
	);

	if (result == NULL)
	{
		return _GetLastNetError();
	}

	return EOK;
}

inline int _ConvertNetAddressToSockInAddr(const NetAddress *address, NetPort port, SockInAddress *output) {
	const short native_addr_type = _AddressTypeToNative(address->type);
	InAddress in_addr = {0};

	const int in_addr_conv_result = _ConvertNetAddressToInAddr(address, &in_addr);

	if (in_addr_conv_result != EOK)
	{
		// TODO: error printout
		return in_addr_conv_result;
	}

	// they two overlap
	output->data.addr.sin_family = native_addr_type;
	output->data.addr.sin_port = port;

	if (address->type == eNAddrType_IPv6)
	{
		output->length = sizeof(output->data.addr6);
		output->data.addr6.sin6_addr = in_addr.data.ipv6;
		return EOK;
	}


	output->length = sizeof(output->data.addr);
	output->data.addr.sin_addr = in_addr.data.ipv4;

	return EOK;
}

inline int _HostNameToAddressList(NetPort port, NetAddressType address_type,
																	NetConnectionProtocol conn_protocol, AddressList *output) {
	static const char *nodename = NULL;

	ADDRINFO hints = {0};

	hints.ai_flags = 0;
	hints.ai_family = _AddressTypeToNative(address_type);
	hints.ai_protocol = _ConnectionProtocolToNativeIP(conn_protocol);
	hints.ai_socktype = _ConnectionProtocolToNativeST(conn_protocol);

	ADDRINFO *info_list = NULL;

	char port_str[16] = {0};

	_ultoa_s(port, port_str, ARRAYSIZE(port_str), 10);

	const int error_code = getaddrinfo(nodename, port_str, &hints, &info_list);

	if (error_code != EOK)
	{
		// error code is not contained withing _GetLastNetError()
		return _ReportError(
			error_code,

			"getaddrinfo(\"%d\", NULL, %p, %p) failed",

			port, &hints, &info_list
		);
	}


	for (ADDRINFO *current_info = info_list;
			 current_info != NULL; current_info = current_info->ai_next)
	{
		const SockInAddress sock_address =
			_SockInAddrFromDynamicSockAddr(current_info->ai_addr, (int)current_info->ai_addrlen);

		const InAddress in_address = _InAddrFromSockInAddr(&sock_address);

		NetAddress net_address = {0};
		(void)_ConvertInAddrToNetAddress(&in_address, &net_address);

		printf("getaddrinfo address at %p: \"%s\"\n", current_info, net_address.name);

	}

	freeaddrinfo(info_list);

	return EOK;
}

inline SockInAddress _SockInAddrFromDynamicSockAddr(const SOCKADDR *addr, const int length) {
	SockInAddress result = {0};

	result.length = length;

	if (length == sizeof(SOCKADDR_IN))
	{
		result.data.addr = *(SOCKADDR_IN *)addr;
	}

	else if (length == sizeof(SOCKADDR_IN6))
	{
		result.data.addr6 = *(SOCKADDR_IN6 *)addr;
	}

	else
	{
		//! UNKNOWN TYPE
	}

	return result;
}

inline InAddress _InAddrFromSockInAddr(const SockInAddress *sock_in_addr) {
	InAddress result;

	//* IPv6
	if (sock_in_addr->length == sizeof(SOCKADDR_IN6))
	{
		result.length = sizeof(IN6_ADDR);
		result.data.ipv6 = sock_in_addr->data.addr6.sin6_addr;
	}
	//* IPv4
	else if (sock_in_addr->length == sizeof(SOCKADDR_IN))
	{
		result.length = sizeof(IN_ADDR);
		result.data.ipv4 = sock_in_addr->data.addr.sin_addr;
	}
	//* UNKNOWN
	else
	{
		result.length = 0;
	}

	return result;
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

// for portablity
inline errno_t _GetLastNetError() {
	return WSAGetLastError();
}

// returns the error name
// if the error_code has no name (i.e not a valid/known error code), 
// then the hex representation of the error code will be returned
// ----
// returns value should not be freed!
inline const char *_GetErrorName(const errno_t error_code) {
	enum { template_str_size = 16, hex_radix = 16 };

	static char template_str[template_str_size] = {'0', 'x'};
	switch (error_code)
	{
		ERROR_ENTRY(EPERM);
		ERROR_ENTRY(ENOENT);
		ERROR_ENTRY(ESRCH);
		ERROR_ENTRY(EINTR);
		ERROR_ENTRY(EIO);
		ERROR_ENTRY(ENXIO);
		ERROR_ENTRY(E2BIG);
		ERROR_ENTRY(ENOEXEC);
		ERROR_ENTRY(EBADF);
		ERROR_ENTRY(ECHILD);
		ERROR_ENTRY(EAGAIN);
		ERROR_ENTRY(ENOMEM);
		ERROR_ENTRY(EACCES);
		ERROR_ENTRY(EFAULT);
		ERROR_ENTRY(EBUSY);
		ERROR_ENTRY(EEXIST);
		ERROR_ENTRY(EXDEV);
		ERROR_ENTRY(ENODEV);
		ERROR_ENTRY(ENOTDIR);
		ERROR_ENTRY(EISDIR);
		ERROR_ENTRY(ENFILE);
		ERROR_ENTRY(EMFILE);
		ERROR_ENTRY(ENOTTY);
		ERROR_ENTRY(EFBIG);
		ERROR_ENTRY(ENOSPC);
		ERROR_ENTRY(ESPIPE);
		ERROR_ENTRY(EROFS);
		ERROR_ENTRY(EMLINK);
		ERROR_ENTRY(EPIPE);
		ERROR_ENTRY(EDOM);
		ERROR_ENTRY(EDEADLK);
		ERROR_ENTRY(ENAMETOOLONG);
		ERROR_ENTRY(ENOLCK);
		ERROR_ENTRY(ENOSYS);
		ERROR_ENTRY(ENOTEMPTY);
		ERROR_ENTRY(EINVAL);
		ERROR_ENTRY(ERANGE);
		ERROR_ENTRY(EILSEQ);
		ERROR_ENTRY(STRUNCATE);
		ERROR_ENTRY(ENOTSUP);
		ERROR_ENTRY(EAFNOSUPPORT);
		ERROR_ENTRY(EADDRINUSE);
		ERROR_ENTRY(EADDRNOTAVAIL);
		ERROR_ENTRY(EISCONN);
		ERROR_ENTRY(ENOBUFS);
		ERROR_ENTRY(ECONNABORTED);
		ERROR_ENTRY(EALREADY);
		ERROR_ENTRY(ECONNREFUSED);
		ERROR_ENTRY(ECONNRESET);
		ERROR_ENTRY(EDESTADDRREQ);
		ERROR_ENTRY(EHOSTUNREACH);
		ERROR_ENTRY(EMSGSIZE);
		ERROR_ENTRY(ENETDOWN);
		ERROR_ENTRY(ENETRESET);
		ERROR_ENTRY(ENETUNREACH);
		ERROR_ENTRY(ENOPROTOOPT);
		ERROR_ENTRY(ENOTSOCK);
		ERROR_ENTRY(ENOTCONN);
		ERROR_ENTRY(ECANCELED);
		ERROR_ENTRY(EINPROGRESS);
		ERROR_ENTRY(EOPNOTSUPP);
		ERROR_ENTRY(EWOULDBLOCK);
		ERROR_ENTRY(EOWNERDEAD);
		ERROR_ENTRY(EPROTO);
		ERROR_ENTRY(EPROTONOSUPPORT);
		ERROR_ENTRY(EBADMSG);
		ERROR_ENTRY(EIDRM);
		ERROR_ENTRY(ENODATA);
		ERROR_ENTRY(ENOLINK);
		ERROR_ENTRY(ENOMSG);
		ERROR_ENTRY(ENOSR);
		ERROR_ENTRY(ENOSTR);
		ERROR_ENTRY(ENOTRECOVERABLE);
		ERROR_ENTRY(ETIME);
		ERROR_ENTRY(ETXTBSY);
		ERROR_ENTRY(ETIMEDOUT);
		ERROR_ENTRY(ELOOP);
		ERROR_ENTRY(EPROTOTYPE);
		ERROR_ENTRY(EOVERFLOW);

		ERROR_ENTRY_WSA(WSABASEERR);
		ERROR_ENTRY_WSA(WSAEINTR);
		ERROR_ENTRY_WSA(WSAEBADF);
		ERROR_ENTRY_WSA(WSAEACCES);
		ERROR_ENTRY_WSA(WSAEFAULT);
		ERROR_ENTRY_WSA(WSAEINVAL);
		ERROR_ENTRY_WSA(WSAEMFILE);
		ERROR_ENTRY_WSA(WSAEWOULDBLOCK);
		ERROR_ENTRY_WSA(WSAEINPROGRESS);
		ERROR_ENTRY_WSA(WSAEALREADY);
		ERROR_ENTRY_WSA(WSAENOTSOCK);
		ERROR_ENTRY_WSA(WSAEDESTADDRREQ);
		ERROR_ENTRY_WSA(WSAEMSGSIZE);
		ERROR_ENTRY_WSA(WSAEPROTOTYPE);
		ERROR_ENTRY_WSA(WSAENOPROTOOPT);
		ERROR_ENTRY_WSA(WSAEPROTONOSUPPORT);
		ERROR_ENTRY_WSA(WSAESOCKTNOSUPPORT);
		ERROR_ENTRY_WSA(WSAEOPNOTSUPP);
		ERROR_ENTRY_WSA(WSAEPFNOSUPPORT);
		ERROR_ENTRY_WSA(WSAEAFNOSUPPORT);
		ERROR_ENTRY_WSA(WSAEADDRINUSE);
		ERROR_ENTRY_WSA(WSAEADDRNOTAVAIL);
		ERROR_ENTRY_WSA(WSAENETDOWN);
		ERROR_ENTRY_WSA(WSAENETUNREACH);
		ERROR_ENTRY_WSA(WSAENETRESET);
		ERROR_ENTRY_WSA(WSAECONNABORTED);
		ERROR_ENTRY_WSA(WSAECONNRESET);
		ERROR_ENTRY_WSA(WSAENOBUFS);
		ERROR_ENTRY_WSA(WSAEISCONN);
		ERROR_ENTRY_WSA(WSAENOTCONN);
		ERROR_ENTRY_WSA(WSAESHUTDOWN);
		ERROR_ENTRY_WSA(WSAETOOMANYREFS);
		ERROR_ENTRY_WSA(WSAETIMEDOUT);
		ERROR_ENTRY_WSA(WSAECONNREFUSED);
		ERROR_ENTRY_WSA(WSAELOOP);
		ERROR_ENTRY_WSA(WSAENAMETOOLONG);
		ERROR_ENTRY_WSA(WSAEHOSTDOWN);
		ERROR_ENTRY_WSA(WSAEHOSTUNREACH);
		ERROR_ENTRY_WSA(WSAENOTEMPTY);
		ERROR_ENTRY_WSA(WSAEPROCLIM);
		ERROR_ENTRY_WSA(WSAEUSERS);
		ERROR_ENTRY_WSA(WSAEDQUOT);
		ERROR_ENTRY_WSA(WSAESTALE);
		ERROR_ENTRY_WSA(WSAEREMOTE);
		ERROR_ENTRY_WSA(WSASYSNOTREADY);
		ERROR_ENTRY_WSA(WSAVERNOTSUPPORTED);
		ERROR_ENTRY_WSA(WSANOTINITIALISED);
		ERROR_ENTRY_WSA(WSAEDISCON);
		ERROR_ENTRY_WSA(WSAENOMORE);
		ERROR_ENTRY_WSA(WSAECANCELLED);
		ERROR_ENTRY_WSA(WSAEINVALIDPROCTABLE);
		ERROR_ENTRY_WSA(WSAEINVALIDPROVIDER);
		ERROR_ENTRY_WSA(WSAEPROVIDERFAILEDINIT);
		ERROR_ENTRY_WSA(WSASYSCALLFAILURE);
		ERROR_ENTRY_WSA(WSASERVICE_NOT_FOUND);
		ERROR_ENTRY_WSA(WSATYPE_NOT_FOUND);
		ERROR_ENTRY_WSA(WSA_E_NO_MORE);
		ERROR_ENTRY_WSA(WSA_E_CANCELLED);
		ERROR_ENTRY_WSA(WSAEREFUSED);
		ERROR_ENTRY_WSA(WSAHOST_NOT_FOUND);
		ERROR_ENTRY_WSA(WSATRY_AGAIN);
		ERROR_ENTRY_WSA(WSANO_RECOVERY);
		ERROR_ENTRY_WSA(WSANO_DATA);
		ERROR_ENTRY_WSA(WSA_QOS_RECEIVERS);
		ERROR_ENTRY_WSA(WSA_QOS_SENDERS);
		ERROR_ENTRY_WSA(WSA_QOS_NO_SENDERS);
		ERROR_ENTRY_WSA(WSA_QOS_NO_RECEIVERS);
		ERROR_ENTRY_WSA(WSA_QOS_REQUEST_CONFIRMED);
		ERROR_ENTRY_WSA(WSA_QOS_ADMISSION_FAILURE);
		ERROR_ENTRY_WSA(WSA_QOS_POLICY_FAILURE);
		ERROR_ENTRY_WSA(WSA_QOS_BAD_STYLE);
		ERROR_ENTRY_WSA(WSA_QOS_BAD_OBJECT);
		ERROR_ENTRY_WSA(WSA_QOS_TRAFFIC_CTRL_ERROR);
		ERROR_ENTRY_WSA(WSA_QOS_GENERIC_ERROR);
		ERROR_ENTRY_WSA(WSA_QOS_ESERVICETYPE);
		ERROR_ENTRY_WSA(WSA_QOS_EFLOWSPEC);
		ERROR_ENTRY_WSA(WSA_QOS_EPROVSPECBUF);
		ERROR_ENTRY_WSA(WSA_QOS_EFILTERSTYLE);
		ERROR_ENTRY_WSA(WSA_QOS_EFILTERTYPE);
		ERROR_ENTRY_WSA(WSA_QOS_EFILTERCOUNT);
		ERROR_ENTRY_WSA(WSA_QOS_EOBJLENGTH);
		ERROR_ENTRY_WSA(WSA_QOS_EFLOWCOUNT);
		ERROR_ENTRY_WSA(WSA_QOS_EUNKNOWNPSOBJ);
		// ERROR_ENTRY_WSA(WSA_QOS_EUNKOWNPSOBJ);
		ERROR_ENTRY_WSA(WSA_QOS_EPOLICYOBJ);
		ERROR_ENTRY_WSA(WSA_QOS_EFLOWDESC);
		ERROR_ENTRY_WSA(WSA_QOS_EPSFLOWSPEC);
		ERROR_ENTRY_WSA(WSA_QOS_EPSFILTERSPEC);
		ERROR_ENTRY_WSA(WSA_QOS_ESDMODEOBJ);
		ERROR_ENTRY_WSA(WSA_QOS_ESHAPERATEOBJ);
		ERROR_ENTRY_WSA(WSA_QOS_RESERVED_PETYPE);
	default:
		_ultoa_s(error_code, template_str + 2, template_str_size - 2, hex_radix);
		return template_str;
	}
}

#pragma endregion
