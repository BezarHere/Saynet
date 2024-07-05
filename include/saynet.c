#include "saynet.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define NOSERVICE
#define NOMCX
#define NOIME

#include <winsock2.h>
#include <ws2tcpip.h>

#undef NOSERVICE
#undef NOMCX
#undef NOIME

#else
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#endif


// #pragma comment(lib, "Ws2_32.lib")

#ifdef _WIN32
#define WSA_NETWORK
#endif

#define OUT
#define INOUT

#define EOK 0

#define BOOL_ALPHA(cond) ((cond) ? "true" : "false")

#define ASSERT_CODE_RET(code) if ((code) != EOK) return code

#define ASSERT_CLIENT_CREATION(code) if ((code) != EOK) \
{return code; _AbortClient(client, "creation failure");}

#define ASSERT_SERVER_CREATION(code) if ((code) != EOK) \
{return code; _AbortServer(server, "creation failure");} 

#define VERBOSE(...) printf(__VA_ARGS__)

#define ERROR_ENTRY(name) case name: return (#name) + 1

// skip the 'WSA' part
#define ERROR_ENTRY_WSA(name) case name: return (#name)

#define ERR_LOG(code, msg) _Error(code, "%s:%d::" msg, __FUNCTION__, __LINE__)
#define ERR_LOG_V(code, msg, ...) _Error(code, "%s:%d::" msg, __FUNCTION__, __LINE__, __VA_ARGS__)

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

	MaxAddressListSize = 24,

	// max number of net objects (clients + servers)
	MaxNetServiceKeys = 32,
	// the value of an empty key
	ServiceEmptyKey = 0,
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

typedef struct SocketAddress
{
	union _SocketAddress_data
	{
		SOCKADDR_IN addr;
		SOCKADDR_IN6 addr6;
	} data;
	int length;
} SocketAddress;

typedef uint64_t ServiceKey;

typedef struct NetInternalData
{
	size_t recv_buffer_sz;
	uint8_t *recv_buffer;

	ServiceKey service_key;

	NetCreateParams connection_params;
} NetInternalData;

typedef struct AddressListNode
{
	NetAddress net_address;
	SocketAddress sock_inaddr;
	InAddress inaddr;
} AddressListNode;

typedef struct AddressList
{
	size_t count;
	AddressListNode data[MaxAddressListSize];
} AddressList;

typedef struct SocketInfo
{
	NetAddressType type;
	NetConnectionProtocol protocol;
	SocketAddress local_address;
	SocketAddress remote_address;
} SocketInfo;

static struct NetService
{
#ifdef WSA_NETWORK
	WSADATA wsa;
#endif
	struct NetServiceNode
	{
		NetInternalData *internal;
		ServiceKey key;
	};

	// TODO: replace this with an array of NetServiceNodes
	ServiceKey keys[MaxNetServiceKeys];
} g_service = {};

typedef int (*CallUseAddressProc)(SOCKET, const SOCKADDR *, int);

static inline int _LoadNetService(OUT ServiceKey *key);
static inline int _UnloadNetService(ServiceKey key);

static inline ServiceKey S_CreateKey();
static inline ServiceKey S_GenerateUniqueKey(size_t pos);

static inline bool S_ServiceHasKeys();
static inline size_t S_ServiceKeyCount();
// -1 if not found
static inline int S_ServiceFindKey(ServiceKey key);
// -1 if non are found
static inline int S_ServiceFindEmptyKey();

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
static inline int _SocketToListen(NetSocket socket, const NetCreateParams *params);
static inline int _MarkSocketNonBlocking(NetSocket socket);
static inline int _SocketSetBlocking(NetSocket socket, bool value);
static inline int _SocketSetBroadcast(NetSocket socket, bool value);

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

// will not display the code if it's EOK
static inline int _Error(int code, const char *format, ...);
// will not display the code if it's EOK
static inline int _Warning(int code, const char *format, ...);

static inline void _PutColor(FILE *out_fp, ConsoleColor color);

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
																								 SocketAddress *output);

static inline int _GetSocketInfo(NetSocket socket, OUT SocketInfo *output);

static inline int _HostNameToAddressList(NetPort port, NetAddressType address_type,
																				 NetConnectionProtocol conn_protocol,
																				 AddressList *output);

static inline SocketAddress _SockInAddrFromDynamicSockAddr(const SOCKADDR *addr, int length);
static inline InAddress _InAddrFromSockInAddr(const SocketAddress *sock_in_addr);

static inline int _ProcessGeneralCreateParams(NetCreateParams *params);
static inline int _ProcessServerCreateParams(NetCreateParams *params);
static inline int _ProcessClientCreateParams(NetCreateParams *params);

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
	NetCreateParams processed_params = *params;

	// replaced 'params' by 'processed_params'
	{
		result_code = _ProcessClientCreateParams(&processed_params);
		ASSERT_CLIENT_CREATION(result_code);
		params = &processed_params;
	}

	_DestroyInternalData(client->_internal);
	client->_internal = _CreateInternalData();
	client->_internal->connection_params = *params;

	result_code = _LoadNetService(&client->_internal->service_key);
	ASSERT_CLIENT_CREATION(result_code);


	_HostNameToAddressList(params->address.port, params->address.type, params->protocol, NULL);

	result_code = _CreateSocket(&client->socket, params);
	ASSERT_CLIENT_CREATION(result_code);

	if (params->protocol == eNConnectProto_TCP)
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
	NetCreateParams processed_params = *params;

	// replaced 'params' by 'processed_params'
	{
		result_code = _ProcessClientCreateParams(&processed_params);
		ASSERT_SERVER_CREATION(result_code);
		params = &processed_params;
	}

	_DestroyInternalData(server->_internal);
	server->_internal = _CreateInternalData();
	server->_internal->connection_params = *params;

	result_code = _LoadNetService(&server->_internal->service_key);
	ASSERT_SERVER_CREATION(result_code);


	result_code = _InitSocket(&server->socket, params);
	ASSERT_SERVER_CREATION(result_code);

	if (params->protocol == eNConnectProto_TCP)
	{
		result_code = _SocketToListen(server->socket, params);
		ASSERT_SERVER_CREATION(result_code);
	}

	NetAddressBuffer buffer = {0};

	_GetSocketAddr(server->socket, &buffer);

	printf("server %llu hosted at %s\n", server->socket, buffer);

	return result_code;
}

errno_t NetCloseClient(NetClient *client) {
	// TODO: check return value
	_UnloadNetService(client->_internal->service_key);

	_DestroyInternalData(client->_internal);
	client->_internal = NULL;

	_CloseSocket(client->socket);
	client->socket = INVALID_SOCKET;

	return EOK;
}

errno_t NetCloseServer(NetServer *server) {
	// TODO: check return value
	_UnloadNetService(server->_internal->service_key);

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

	return EOK;
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
		return ERR_LOG_V(
			E2BIG,

			"server receive buffer is too big, buffer size is %llu bytes, max size is %d bytes",
			server->_internal->recv_buffer_sz, INT32_MAX
		);
	}

	if (server->_internal->connection_params.protocol != eNConnectProto_TCP)
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
	SocketAddress sock_addr = {0};

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

		return ERR_LOG_V(
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

		return ERR_LOG_V(
			error,

			"client failed to send buffer %p, length %llu bytes in socket %llu",
			data, original_size, client->socket
		);
	}

	return EOK;
}

errno_t NetServerSend(NetServer *server, const NetClientID *client, const void *data, size_t *size) {
	const size_t original_size = *size;
	int result = 0;

	result = send(client->socket, data, original_size, 0);

	printf(
		"sending stuff to client %llu \"%s\":%d\n",
		client->socket,
		client->address.name,
		NetServerGetCreateParams(server)->address.port
	);

	if (result == SOCKET_ERROR)
	{
		const int error = _GetLastNetError();

		*size = 0;

		if (_IsSocketDisconnectionError(error))
		{
			_AbortServer(server, "server disconnected");
		}

		return ERR_LOG_V(
			error,

			"server failed to sendto \"%s\":%d buffer %p, length %llu bytes through socket %llu -> %llu",
			client->address.name,
			NetServerGetCreateParams(server)->address.port,
			data,
			original_size,
			server->socket,
			client->socket
		);
	}

	*size = result;

	return EOK;
}

errno_t NetServerKickCLient(NetServer *server, const NetClientID *client_id, const char *reason) {

	NetClientIDListNode *node = _ExtractNodeWithClientID(&server->p_client_ids, client_id);

	if (node == NULL)
	{
		return ERR_LOG_V(
			ENOENT,

			"No client has the id {socket=%llu, address=\"%.*s\"}",
			client_id->socket,
			ARRAYSIZE(client_id->address.name),
			client_id->address.name
		);
	}

	_CloseClientID(client_id);

	if (server->proc_client_left)
	{
		server->proc_client_left(client_id);
	}

	_FreeClientIDNode(node);

	VERBOSE(
		"removed client id {socket=%llu, address=\"%.*s\"}, reason=%s",
		client_id->socket,
		(int)ARRAYSIZE(client_id->address.name),
		client_id->address.name,
		reason
	);

	return EOK;
}

#pragma endregion

#pragma region(utility)

inline int _LoadNetService(OUT ServiceKey *key) {
	const bool already_started = S_ServiceHasKeys();

	// output key
	{
		ServiceKey new_key = S_CreateKey();

		if (new_key == ServiceEmptyKey)
		{
			return ERR_LOG_V(
				ENOSPC,

				"couldn't create a SAYNET service key; svc key count=%llu, max key count=%d",
				S_ServiceKeyCount(),
				MaxNetServiceKeys
			);
		}

		*key = new_key;
	}

	if (already_started)
	{
		return EOK;
	}

	int result_code = EOK;

#ifdef WSA_NETWORK
	result_code = WSAStartup(WINSOCK_VERSION, &g_service.wsa);

	if (result_code != EOK)
	{
		return ERR_LOG(
			_GetLastNetError(),

			"wsa startup failed, net service can't be run"
		);
	}
#endif

	return EOK;
}

inline int _UnloadNetService(const ServiceKey key) {

	// clear key
	{
		const int key_pos = S_ServiceFindKey(key);

		if (key_pos == -1)
		{
			return ERR_LOG_V(
				ENOENT,

				"no valid service key found with the value %llu, svc key count=%llu",
				key, S_ServiceKeyCount()
			);
		}

		g_service.keys[key_pos] = ServiceEmptyKey;
	}

	// if there is still some service keys, do not close the library
	if (S_ServiceHasKeys())
	{
		return EOK;
	}

	int result_code = EOK;

#ifdef WSA_NETWORK
	result_code = WSACleanup();

	if (result_code != EOK)
	{
		return ERR_LOG(
			_GetLastNetError(),

			"wsa cleanup failed, what did you do for this? this shouldn't happen normally"
		);
	}
#endif

	return EOK;
}

inline ServiceKey S_CreateKey() {
	for (size_t i = 0; i < MaxNetServiceKeys; i++)
	{
		if (g_service.keys[i] == ServiceEmptyKey)
		{
			g_service.keys[i] = S_GenerateUniqueKey(i);

			return g_service.keys[i];
		}
	}

	return ServiceEmptyKey;
}

inline ServiceKey S_GenerateUniqueKey(size_t pos) {
	static const ServiceKey init_seed = (ServiceKey)0x283b5d77b3d5113b;
	return _rotl64(init_seed, (int)pos) ^ ~_rotl64(init_seed + pos, -(int)pos);
}

inline bool S_ServiceHasKeys() {
	for (size_t i = 0; i < MaxNetServiceKeys; i++)
	{
		if (g_service.keys[i] == ServiceEmptyKey)
		{
			continue;
		}

		return true;
	}

	return false;
}

inline size_t S_ServiceKeyCount() {
	size_t count = 0;

	for (size_t i = 0; i < MaxNetServiceKeys; i++)
	{
		if (g_service.keys[i] == ServiceEmptyKey)
		{
			continue;
		}

		count++;
	}

	return count;
}

inline int S_ServiceFindKey(const ServiceKey key) {

	for (int i = 0; i < MaxNetServiceKeys; i++)
	{
		if (g_service.keys[i] == key)
		{
			return i;
		}
	}

	return -1;
}

inline int S_ServiceFindEmptyKey() {

	for (int i = 0; i < MaxNetServiceKeys; i++)
	{
		if (g_service.keys[i] == ServiceEmptyKey)
		{
			return i;
		}
	}

	return -1;
}

inline errno_t _PollServerUDP(NetServer *server) {
	NetAddress address = {0};
	address.type = NetServerGetCreateParams(server)->address.type;

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

		VERBOSE("received %d bytes on udp\n", size);

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
			data.size = size;

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

					(int)ARRAYSIZE(client_id.address.name),
					client_id.address.name,

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

			(int)ARRAYSIZE(client_id.address.name),
			client_id.address.name
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

			if (node->inactivity_hits >= MaxInactivityHits)
			{
				NetServerKickCLient(server, &node->client_id, "inactivity");
			}
			else if (size == -2)
			{
				char buffer[96] = {0};
				sprintf_s(buffer, ARRAYSIZE(buffer), "closed connection [%s]", _GetErrorName(err_code));
				NetServerKickCLient(server, &node->client_id, buffer);
			}

			continue;
		}

		node->inactivity_hits = 0;


		if (size > 0 && server->proc_client_recv)
		{
			NetPacketData packet = {};

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

	address.type = params->address.type;
	memcpy(
		address.name,
		params->address.name,
		ARRAYSIZE(address.name)
	);

	SocketAddress sock_addr = {0};

	int result_code = -1;

	result_code = _ConvertNetAddressToSockInAddr(&address, htons(params->address.port), &sock_addr);

	if (result_code != EOK)
	{
		return ERR_LOG_V(
			result_code,

			"failed to encode address \"%s\" port %d",
			address.name, params->address.port
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
		return ERR_LOG_V(
			result_code,

			"%s: failed; socket=%llu, address=\"%s\", port=%d",
			context,
			socket,
			address.name,
			params->address.port
		);
	}

	return EOK;
}

int _CreateSocket(NetSocket *pSocket, const NetCreateParams *params) {
	*pSocket = socket(
		_AddressTypeToNative(params->address.type),
		_ConnectionProtocolToNativeST(params->protocol),
		_ConnectionProtocolToNativeIP(params->protocol)
	);

	if (*pSocket == INVALID_SOCKET)
	{
		return ERR_LOG(_GetLastNetError(), "Failed to create a socket");
	}

	// FIXME: make this configurable by the user
	_SetInternalBufferSizes(*pSocket, DefaultRecvBufferSz);
	_SetMaxMessageSize(*pSocket, DefaultRecvBufferSz + 256);

	return EOK;
}

int _BindSocket(const NetSocket socket, const NetCreateParams *params) {
	return _CallUseAddress(socket, params, bind, "binding socket");
}

int _SocketToListen(NetSocket socket, const NetCreateParams *params) {
	int result_code = listen(socket, params->max_listen_backlog);

	if (result_code != EOK)
	{
		return ERR_LOG_V(
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
		return ERR_LOG_V(
			result_code,

			"marking the socket %llu as non-blocking failed",
			socket
		);
	}

	return EOK;
}

inline int _SocketSetBlocking(NetSocket socket, bool value) {
	int result_code = -1;

#ifdef WSA_NETWORK
	result_code = ioctlsocket(socket, FIONBIO, (u_long *)&value);

	if (result_code != EOK)
	{
		return ERR_LOG_V(
			result_code,

			"setting the socket blocking mode to %s failed, socket=%llu",
			BOOL_ALPHA(value), socket
		);
	}

#endif

	return result_code;
}

inline int _SocketSetBroadcast(NetSocket socket, bool value) {
	setsockopt(socket, SOL_SOCKET, SOL_SOCKET, (const char *)&value, sizeof(value));
	return 0;
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

		return ERR_LOG_V(
			error,

			"something happened while accepting connections to socket %llu",
			socket
		);
	}

	*found = true;



	client_id->socket = new_socket;
	client_id->address.type = _NativeToAddressType(addr.sa_family);

	// clear address representation
	memclear(client_id->address.name, ARRAYSIZE(client_id->address.name));

	inet_ntop(
		addr.sa_family,
		&addr,
		client_id->address.name,
		ARRAYSIZE(client_id->address.name)
	);

	// to make sure, set the last char to a null termination
	client_id->address.name[ARRAYSIZE(client_id->address.name) - 1] = 0;

	VERBOSE("accepted address %s\n", client_id->address.name);

	return EOK;
}

inline int _GetSocketAddr(NetSocket socket, NetAddressBuffer *address_out) {
	memclear(address_out, ARRAYSIZE(*address_out));

	SOCKADDR addr = {0};
	int length = sizeof(addr);

	int result = getsockname(socket, &addr, &length);

	if (result != EOK)
	{
		return ERR_LOG_V(
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

		return ERR_LOG_V(
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

	// make sure the input buffer size isn't output-ed
	// imagine having a buffer 64KB and suddenly an empty 64KB message arrives?
	*size = 0;

	memclear(address->name, ARRAYSIZE(address->name));

	SocketAddress sock_in_addr = {0};
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

		return ERR_LOG_V(
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
		return ERR_LOG_V(
			_GetLastNetError(),

			"failed to set the SO_RCVBUF for the socket %llu to %d",
			socket,
			new_size
		);
	}

	result_code = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, (const char *)&new_size, sizeof(new_size));
	if (result_code == SOCKET_ERROR)
	{
		return _Warning(
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
		return _Warning(
			_GetLastNetError(),

			"failed to set the SO_MAX_MSG_SIZE for the socket %llu to %d",
			socket,
			new_size
		);
	}

	return EOK;
}

/// @returns any value passed in `code`
int _Error(int code, const char *format, ...) {
	_PutColor(stdout, eFGClr_Red);

	if (code == EOK)
	{
		fputs("ERR:", stdout);
	}
	else
	{
		printf("ERR[%s]:", _GetErrorName(code));
	}

	va_list va_list;
	va_start(va_list, format);
	vprintf(format, va_list);
	va_end(va_list);

	_PutColor(stdout, eFGClr_Clear);
	fputc('\n', stdout);

	return code;
}

inline int _Warning(int code, const char *format, ...) {
	_PutColor(stdout, eFGClr_Red);

	if (code == EOK)
	{
		fputs("WRN:", stdout);
	}
	else
	{
		printf("WRN[%s]:", _GetErrorName(code));
	}

	va_list va_list;
	va_start(va_list, format);
	vprintf(format, va_list);
	va_end(va_list);

	_PutColor(stdout, eFGClr_Clear);
	fputc('\n', stdout);

	return code;
}

void _PutColor(FILE *out_fp, ConsoleColor color) {
	fprintf(out_fp, "\033[%dm", color);
}

inline NetInternalData *_CreateInternalData() {
	NetInternalData *data = malloc(sizeof(*data));
	if (data == NULL)
	{
		ERR_LOG(ENOMEM, "failed to allocate internal data");
		exit(ENOMEM);
		return NULL;
	}

	data->recv_buffer_sz = DefaultRecvBufferSz;
	data->recv_buffer = malloc(data->recv_buffer_sz);

	if (data->recv_buffer == NULL)
	{
		ERR_LOG_V(ENOMEM, "failed to allocate recv buffer: size=%llu bytes", data->recv_buffer_sz);
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
	ERR_LOG_V(E_ABORT, "server: aborted hosting: reason=\"%s\"\n", reason);
	NetCloseServer(server);
}

inline void _AbortClient(NetClient *client, const char *reason) {
	// TODO: colorize/use colorized print function to something like YELLOW
	ERR_LOG_V(E_ABORT, "client: connection aborted: reason=\"%s\"\n", reason);
	NetCloseClient(client);
}

inline NetClientIDListNode *_CreateClientIDNode(const NetClientID *client_id) {
	NetClientIDListNode *node = malloc(sizeof(*node));

	if (node == NULL)
	{
		exit(
			ERR_LOG_V(
				ENOMEM,

				"failed to allocate a client id list node for client id: socket=%llu address=\"%.*s\"",

				client_id->socket,

				ARRAYSIZE(client_id->address.name),
				client_id->address.name
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

inline int _ConvertNetAddressToSockInAddr(const NetAddress *address, NetPort port, SocketAddress *output) {
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

inline int _GetSocketInfo(NetSocket socket, OUT SocketInfo *output) {
	return 0;
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

	// const int error_code = getaddrinfo(nodename, port_str, &hints, &info_list);
	const int error_code = getaddrinfo("broadcast", NULL, &hints, &info_list);

	if (error_code != EOK)
	{
		// error code is not contained withing _GetLastNetError()
		return ERR_LOG_V(
			error_code,

			"getaddrinfo(\"%d\", NULL, %p, %p) failed",

			port, &hints, &info_list
		);
	}


	for (ADDRINFO *current_info = info_list;
			 current_info != NULL; current_info = current_info->ai_next)
	{
		const SocketAddress sock_address =
			_SockInAddrFromDynamicSockAddr(current_info->ai_addr, (int)current_info->ai_addrlen);

		const InAddress in_address = _InAddrFromSockInAddr(&sock_address);

		NetAddress net_address = {0};
		(void)_ConvertInAddrToNetAddress(&in_address, &net_address);

		printf("getaddrinfo address at %p: \"%s\"\n", current_info, net_address.name);

	}

	freeaddrinfo(info_list);

	return EOK;
}

inline SocketAddress _SockInAddrFromDynamicSockAddr(const SOCKADDR *addr, const int length) {
	SocketAddress result = {0};

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

inline InAddress _InAddrFromSockInAddr(const SocketAddress *sock_in_addr) {
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

inline int _ProcessGeneralCreateParams(NetCreateParams *params) {

	if (params->proc_mem_alloc == NULL)
	{
		params->proc_mem_alloc = malloc;
	}

	if (params->proc_mem_free == NULL)
	{
		params->proc_mem_free = free;
	}

	if (params->max_listen_backlog == 0)
	{
		params->max_listen_backlog = SOMAXCONN;
	}


	if (params->protocol != eNConnectProto_TCP && params->protocol != eNConnectProto_UDP)
	{
		return ERR_LOG_V(
			EPROTOTYPE,

			"Unknown protocol type: %d",

			params->protocol
		);
	}

	if (params->address.type != eNAddrType_IPv4 && params->address.type != eNAddrType_IPv6)
	{
		return ERR_LOG_V(
			EAFNOSUPPORT,

			"Unsupported address type: %d",

			params->address.type
		);
	}


	for (int i = NetAddressBufferSize - 1; i >= 0; i--)
	{
		if (params->address.name[i] == 0)
		{
			break;
		}

		// last char, no null character insight
		if (i == 0)
		{
			params->address.name[NetAddressBufferSize - 1] = 0;
			(void)_Warning(
				EBADF,
				("create params's address (\"%s\") has no null termination,"
				 " setting one at the address buffer's end"),
				params->address.name
			);
		}
	}

	return EOK;
}

inline int _ProcessServerCreateParams(NetCreateParams *params) {
	int result_code = 0;

	result_code = _ProcessGeneralCreateParams(params);

	if (result_code != EOK)
	{
		return result_code;
	}

	if (params->broadcast)
	{

	}

	return EOK;
}

inline int _ProcessClientCreateParams(NetCreateParams *params) {
	int result_code = 0;

	result_code = _ProcessGeneralCreateParams(params);

	if (result_code != EOK)
	{
		return result_code;
	}

	if (params->broadcast)
	{
		return ERR_LOG(
			EFAULT,

			"params->broadcast is true, client objects can't broadcast, use a server object instead"
		);
	}

	return EOK;
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
// return value should not be freed!
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
