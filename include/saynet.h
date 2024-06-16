#pragma once
#include <stdint.h>

#ifdef __cplusplus
#define SAYNET_ENUM enum class
#else
#define SAYNET_ENUM enum
#endif

#define SAYNET_API

// constants
enum
{
	NetAddressBufferSize = 32
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
	eNConnectProto_UDB,
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

	struct _NetClientIDListNode *_next;
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

	SAYNET_API errno_t NetCloseClient(NetClient *client, const NetConnectionParams *params);
	SAYNET_API errno_t NetCloseServer(NetServer *server, const NetConnectionParams *params);

	SAYNET_API errno_t NetPollClient(const NetClient *client);
	SAYNET_API errno_t NetPollServer(const NetServer *server);

#ifdef __cplusplus
}
#endif
