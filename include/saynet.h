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

typedef void *NetLibraryHandle;

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

typedef struct NetObjectData
{
};

typedef struct NetClient
{
	NetSocket socket;

	NetLibraryHandle _handle;
} NetClient;

typedef struct NetServer
{
	NetSocket socket;

	NetLibraryHandle _handle;
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
