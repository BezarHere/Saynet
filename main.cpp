#include "include/saynet.h"
#include <iostream>
#include <array>
#include <string.h>

#include <Windows.h>

static bool received_data = false;
static int receive_data(const NetClientID *client_id, NetPacketData data);

int main() {
	std::cout << "choose either 's' for server or 'c' for client: ";
	char c = 0;
	std::cin >> c;

	if (c == 's')
	{
		std::cout << "starting server\n";

		NetServer server = {0};
		server.proc_client_recv = receive_data;

		NetConnectionParams params;
		params.port = 8080;
		params.connection_protocol = NetConnectionProtocol::eNConnectProto_TCP;
		params.address_type = NetAddressType::eNAddrType_IP4;
		memset(params.address, 0, std::size(params.address));

		NetOpenServer(&server, &params);

		while (!received_data && NetIsServerValid(&server))
		{
			NetPollServer(&server);
			Sleep(50);
		}

		NetCloseServer(&server);
	}

	if (c == 'c')
	{
		std::cout << "starting client\n";

		NetClient client = {0};

		NetConnectionParams params;
		params.port = 8080;
		params.connection_protocol = NetConnectionProtocol::eNConnectProto_TCP;
		params.address_type = NetAddressType::eNAddrType_IP4;

		std::string str{};
		std::cin >> str;

		strncpy(params.address, str.c_str(), std::size(params.address));

		NetOpenClient(&client, &params);

		while (NetIsClientValid(&client))
		{
			NetPollClient(&client);
			Sleep(50);
		}

		NetCloseClient(&client);
	}

}

int receive_data(const NetClientID *client_id, NetPacketData data) {
	static constexpr std::array<char, 16> hex_arr = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};

	constexpr char close_key[] = "close";

	std::cout << "received " << data.size << " bytes from " << client_id->address << '\n';

	for (size_t i = 0; i < data.size; i++)
	{
		// std::cout << (hex_arr[data.data[i] >> 4]) << (hex_arr[data.data[i] & 0xf]);
		std::cout << (char)data.data[i];
	}

	std::cout << '\n';

	if (strncmp((const char *)data.data, close_key, std::size(close_key) - 1) == 0)
	{
		received_data = true;
		std::cout << "closing!\n";
	}

	return 0;
}
