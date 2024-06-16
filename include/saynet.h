#pragma once
#include <stdint.h>

#ifdef __cplusplus
#define SAYNET_ENUM enum class
#else
#define SAYNET_ENUM enum
#endif

#define SAYNET_API

typedef uint64_t NetSocket;
typedef void *NetLibraryHandle;

typedef SAYNET_ENUM NetConnectionProtocol
{
	eNConnectProto_TCP,
	eNConnectProto_UDB,
} NetConnectionProtocol;

typedef struct NetConnectionParams
{
	NetConnectionProtocol connection_protocol;
} NetConnectionParams;

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

	SAYNET_API errno_t NetStartServer(NetServer *server, const NetConnectionParams *params);



#ifdef __cplusplus
}
#endif
