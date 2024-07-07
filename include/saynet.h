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

#ifndef SAYNET_API
#define SAYNET_API
#endif

#ifndef EOK
#define EOK 0
#endif

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

typedef NetConnectionProtocol NetSocketType;

typedef SAYNET_ENUM NetAddressType
{
	eNAddrType_IPv4,
	eNAddrType_IPv6,
} NetAddressType;

typedef SAYNET_ENUM NetSocketFlags
{
	eNSockFlag_None = 0x00,
	eNSockFlag_Writeable = 0x01,
	eNSockFlag_Readable = 0x02,
} NetSocketFlags;

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

	// max number of clients that can be waiting to join (SERVER EXCLUSIVE, CLIENTS IGNORE VALUE)
	// clients will only be able to join when the server polls (you can deny acceptance using the callback)
	// set to zero to use the default value (driver/network service dependent)
	uint32_t max_listen_backlog;

	// function to call internally to allocate memory, leave as NULL for the internal implementation
	NetMemoryAllocProc proc_mem_alloc;

	// function to call internally to free memory, leave as NULL for the internal implementation
	NetMemoryFreeProc proc_mem_free;
} NetCreateParams;

typedef struct NetClientID
{
	NetSocket socket;
	NetAddress address;
	void *userdata;
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

/// @brief called when an operation of some client failed
/// @returns non-zero if we should kick the client
typedef int (*NetClientFailureProc)(const struct NetClientID *client_id, errno_t error);

/// @brief TCP receive callback for servers
/// @return if the return value is not zero, then the client will know that the packet is bad (or such)
/// @see on UDP, see NetUDPRecvProc
/// @note packet data is owned/freed by saynet, copy the packet to a new buffer to keep after callback
typedef int (*NetClientRecvProc)(const struct NetClientID *client_id, NetPacketData packet_data);

/// @brief TCP receive callback for clients
/// @note the packet data is freed by saynet, copy to retain data
typedef int (*NetServerRecvProc)(NetPacketData packet_data);

// UDP callback for receiving data packets
// make sure to not accept data from malicious sources 
// packet data is owned/freed by saynet, copy the packet to a new buffer to keep after callback
typedef int (*NetUDPRecvProc)(const NetAddress *address, NetPacketData packet_data);

// internal and readonly properties of net objects
typedef struct NetInternalData *NetInternalHandle;

typedef struct _NetObject
{
	void *userdata;

	// readonly
	NetSocket socket;
	// readonly
	NetInternalHandle _internal;
} _NetObject;

typedef struct NetClient
{
	NetServerRecvProc proc_server_recv;
	NetUDPRecvProc proc_udp_recv;

	// base (readonly)
	_NetObject _base;
} NetClient;

typedef struct NetServer
{
	// client joined callback (TCP)
	NetClientJoinedProc proc_client_joined;

	// client left callback (TCP)
	NetClientLeftProc proc_client_left;

	// TCP receive proc
	NetClientRecvProc proc_client_recv;

	// UDP receive proc
	NetUDPRecvProc proc_udp_recv;

	NetClientIDListNode *p_client_ids;

	// base (readonly)
	_NetObject _base;
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
	/// @param client the client that will send the data
	/// @param data the data
	/// @param count [in/out] in the data length, out the amount of bytes sent (can be less then the data length)
	/// @return error if failed, zero at success
	SAYNET_API errno_t NetClientSend(NetClient *client, const void *data, size_t *size);

	/// @brief send data to the client, only works in TCP (for UPD, see NetClientSendToUDP)
	/// @param server the server that will send the data
	/// @param client the client id that is going to receive the data 
	/// @param data the data
	/// @param count [in/out] in the data length, out the amount of bytes sent (can be less then the data length)
	/// @return error if failed, zero at success
	SAYNET_API errno_t NetServerSend(NetServer *server, const NetClientID *client, const void *data, size_t *size);

	// 'reason' is not owned by the function
	SAYNET_API errno_t NetServerKickCLient(NetServer *server, const NetClientID *client_id, const char *reason);

	/// @returns the error state of the client, 0 for valid clients
	SAYNET_API errno_t NetGetClientError(const NetClient *client);
	/// @returns the error state of the server, 0 for valid servers
	SAYNET_API errno_t NetGetServerError(const NetServer *server);

#ifdef __cplusplus
}
#endif
