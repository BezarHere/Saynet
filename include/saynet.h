#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
#define SAYNET_ENUM enum class
#else
#define SAYNET_ENUM enum
#endif

#define SAYNET_API

// constants
enum
{
	NetAddressBufferSize = 48 // for ipv4 & ipv6
};

typedef uint64_t NetSocket;
typedef uint16_t NetPort;

typedef char NetChar;

typedef struct NetPacketData
{
	size_t size;
	uint8_t *data;
} NetPacketData;

typedef struct NetPacketDataView
{
	size_t size;
	const uint8_t *data;
} NetPacketDataView;

struct NetClientID;

// will kick the client if the returns value is non-zero
typedef int (*NetClientJoinedProc)(const struct NetClientID *client_id);
// user has to free the packet data, return value indicates the state of the packet
// if the return value is not zero, then the client will know that the packet is bad (or such)
typedef int (*NetClientRecvProc)(const struct NetClientID *client_id, NetPacketData packet_data);


typedef SAYNET_ENUM NetConnectionProtocol
{
	eNConnectProto_TCP,
	eNConnectProto_UDP,
} NetConnectionProtocol;

typedef SAYNET_ENUM NetAddressType
{
	eNAddrType_IP4,
	eNAddrType_IP6,
} NetAddressType;


typedef char NetAddressBuffer[NetAddressBufferSize];
typedef struct NetConnectionParams
{
	NetConnectionProtocol connection_protocol;

	NetAddressType address_type;
	// null terminated address, can be ipv4 (XX.XX.XX.XX) or ipv6 (NN:NN:...)
	// setting all bytes to '0' will make saynet treat it as take any available address
	NetAddressBuffer address;
	NetPort port;

} NetConnectionParams;


typedef struct NetClientID
{
	NetSocket socket;
	NetAddressType address_type;
	NetAddressBuffer address;
} NetClientID;

typedef struct NetClientIDListNode
{
	NetClientID client_id;
	uint32_t inactivity_hits;

	struct NetClientIDListNode *_next;
} NetClientIDListNode;

typedef struct NetInternalData *NetInternalHandle;

typedef struct NetClient
{
	NetSocket socket;

	NetInternalHandle _handle;
} NetClient;

typedef struct NetServer
{
	NetSocket socket;

	NetClientJoinedProc proc_client_joined;
	NetClientRecvProc proc_client_recv;

	NetClientIDListNode *p_client_ids;

	NetInternalHandle _handle;
} NetServer;


#ifdef __cplusplus
extern "C" {
#endif

	SAYNET_API errno_t NetOpenClient(NetClient *client, const NetConnectionParams *params);
	SAYNET_API errno_t NetOpenServer(NetServer *server, const NetConnectionParams *params);

	SAYNET_API errno_t NetCloseClient(NetClient *client);
	SAYNET_API errno_t NetCloseServer(NetServer *server);

	SAYNET_API errno_t NetPollClient(NetClient *client);
	SAYNET_API errno_t NetPollServer(NetServer *server);

	/// @brief 
	/// @param client 
	/// @param data 
	/// @param count [in/out] in the data length, out the amount of bytes sent (can be less then the data length)
	/// @return error if failed, zero at success
	SAYNET_API errno_t NetClientSend(NetClient *client, const void *data, size_t *size);

	// 'reason' is not owned by the function
	SAYNET_API errno_t NetServerKickCLient(NetServer *server, const NetClientID *client_id, const char *reason);


	static inline bool NetIsClientValid(const NetClient *client) {
		return client != NULL && client->_handle != NULL;
	}

	static inline bool NetIsServerValid(const NetServer *server) {
		return server != NULL && server->_handle != NULL;
	}

#ifdef __cplusplus
}
#endif
