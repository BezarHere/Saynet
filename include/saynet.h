/*
* SayNet
* simple networking library, capable of TCP or UDP in IPv4/6
*
* Zahr abdulatif babker (C) 2023-2024
*/
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

typedef SAYNET_ENUM NetConnectionProtocol
{
	eNConnectProto_TCP,
	eNConnectProto_UDP,
} NetConnectionProtocol;

typedef SAYNET_ENUM NetAddressType
{
	eNAddrType_IPv4,
	eNAddrType_IPv6,
} NetAddressType;

typedef char NetAddressBuffer[NetAddressBufferSize];

typedef struct NetAddress
{
	NetAddressType type;
	NetAddressBuffer name;
} NetAddress;

typedef struct NetUserAddress
{
	NetAddressType type;
	NetAddressBuffer name;
	NetPort port;
} NetUserAddress;

typedef void *(*NetMemoryAllocProc)(const size_t size);
typedef void (*NetMemoryFreeProc)(void *ptr);

typedef struct NetCreateParams
{
	NetConnectionProtocol protocol;

	NetUserAddress address;

	// set to true to make this a broadcast server (NOTE: ONLY WORKS ON SERVERS)
	// broadcast servers skip the address and the protocol altogether
	bool broadcast;

	// function to call internally to allocate memory, leave as NULL for the internal implementation
	NetMemoryAllocProc proc_mem_alloc;

	// function to call internally to free memory, leave as NULL for the internal implementation
	NetMemoryFreeProc proc_mem_free;
} NetCreateParams;

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

// will kick the client if the returns value is non-zero
typedef int (*NetClientJoinedProc)(const struct NetClientID *client_id);

typedef void (*NetClientLeftProc)(const struct NetClientID *client_id);

/// @brief TCP receive callback for servers
/// @return if the return value is not zero, then the client will know that the packet is bad (or such)
/// @see on UDP, see NetRecvProc
/// @note packet data is owned/freed by saynet, copy the packet to a new buffer to keep after callback
typedef int (*NetClientRecvProc)(const struct NetClientID *client_id, NetPacketData packet_data);

/// @brief TCP receive callback for clients
/// @note the packet data is freed by saynet, copy to retain data
typedef int (*NetServerRecvProc)(NetPacketData packet_data);

// UDP callback for receiving data packets
// make sure to not accept data from malicious sources 
// packet data is owned/freed by saynet, copy the packet to a new buffer to keep after callback
typedef int (*NetRecvProc)(const NetAddress *address, NetPacketData packet_data);

typedef struct NetInternalData *NetInternalHandle;

typedef struct NetClient
{
	NetSocket socket;

	NetServerRecvProc proc_server_recv;

	NetInternalHandle _internal;
} NetClient;

typedef struct NetServer
{
	NetSocket socket;

	// client joined callback (TCP)
	NetClientJoinedProc proc_client_joined;

	// client left callback (TCP)
	NetClientLeftProc proc_client_left;

	// TCP receive proc
	NetClientRecvProc proc_client_recv;

	// UDP receive proc
	NetRecvProc proc_udp_recv;

	NetClientIDListNode *p_client_ids;

	NetInternalHandle _internal;
} NetServer;


#ifdef __cplusplus
extern "C" {
#endif

	SAYNET_API errno_t NetOpenClient(NetClient *client, const NetCreateParams *params);
	SAYNET_API errno_t NetOpenServer(NetServer *server, const NetCreateParams *params);

	SAYNET_API errno_t NetCloseClient(NetClient *client);
	SAYNET_API errno_t NetCloseServer(NetServer *server);

	SAYNET_API errno_t NetPollClient(NetClient *client);
	SAYNET_API errno_t NetPollServer(NetServer *server);

	SAYNET_API const NetCreateParams *NetClientGetCreateParams(const NetClient *client);
	SAYNET_API const NetCreateParams *NetServerGetCreateParams(const NetServer *server);

	/// @param count [in/out] in the data length, out the amount of bytes sent (can be less then the data length)
	/// @return error if failed, zero at success
	SAYNET_API errno_t NetClientSendToUDP(NetClient *client,
																				const void *data, size_t *size,
																				const NetUserAddress *address);

	/// @brief send data to the server, only works in TCP (for UPD, see NetClientSendToUDP)
	/// @param client 
	/// @param data 
	/// @param count [in/out] in the data length, out the amount of bytes sent (can be less then the data length)
	/// @return error if failed, zero at success
	SAYNET_API errno_t NetClientSend(NetClient *client, const void *data, size_t *size);

	// 'reason' is not owned by the function
	SAYNET_API errno_t NetServerKickCLient(NetServer *server, const NetClientID *client_id, const char *reason);


	static inline bool NetIsClientValid(const NetClient *client) {
		return client != NULL && client->_internal != NULL;
	}

	static inline bool NetIsServerValid(const NetServer *server) {
		return server != NULL && server->_internal != NULL;
	}

#ifdef __cplusplus
}
#endif
