#include "include/saynet.h"
#include <iostream>
#include <array>
#include <string.h>

#include <Windows.h>

static bool received_data = false;
static int receive_data(const NetClientID *client_id, NetPacketData data);
static int receive_data_udp(const NetAddress *address, NetPacketData data) {
	NetClientID client_id = {};
	strcpy_s(client_id.address, address->name);
	client_id.address_type = address->type;

	return receive_data(&client_id, data);
}

int main() {
	std::cout << "choose either 's' for server or 'c' for client: ";
	char c = 0;
	std::cin >> c;

	NetConnectionParams params;
	params.address_type = NetAddressType::eNAddrType_IPv4;
	params.port = 0x1111;
	params.connection_protocol = NetConnectionProtocol::eNConnectProto_UDP;

	if (c == 's')
	{
		std::cout << "starting server\n";

		NetServer server = {0};
		server.proc_client_recv = receive_data;
		server.proc_udp_recv = receive_data_udp;

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


		std::cout << "server address: ";
		std::string str{};
		std::cin >> str;


		strncpy(params.address, str.c_str(), std::size(params.address));

		params.port += 1;
		NetOpenClient(&client, &params);


		NetUserAddress user_address;
		user_address.port = params.port - 1;

		if (params.connection_protocol == NetConnectionProtocol::eNConnectProto_UDP)
		{
			user_address.type = params.address_type;

			std::cout << "send udp address (* for the server address): ";
			std::cin >> str;

			if (str == "*")
			{
				strcpy_s(user_address.name, params.address);
			}
			else
			{
				strcpy_s(user_address.name, str.c_str());
			}

		}

		while (NetIsClientValid(&client))
		{
			std::string data{};
			std::cin >> data;

			if (!data.empty())
			{
				size_t size = data.size() + 1;
				if (params.connection_protocol == NetConnectionProtocol::eNConnectProto_TCP)
				{
					NetClientSend(&client, data.c_str(), &size);
				}
				else
				{
					NetClientSendToUDP(&client, data.c_str(), &size, &user_address);
				}
				std::cout << "sent " << size << " bytes!\n";
			}

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
