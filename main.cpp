#include "include/saynet.h"
#include <iostream>
#include <array>
#include <string.h>

#include <Windows.h>

static bool close_requested = false;
static int client_joined(const NetClientID *client_id);
static void client_left(const NetClientID *client_id);
static int receive_data(const NetClientID *client_id, NetPacketData data);
static int receive_data_udp(const NetAddress *address, NetPacketData data) {
	NetClientID client_id = {};
	strcpy_s(client_id.address.name, address->name);
	client_id.address.type = address->type;

	return receive_data(&client_id, data);
}

static void *net_obj = nullptr;
static char *response =
"HTTP/1.0 200 OK\nContent-type: text/html\n\n";
static int client_joined_counter = 0;

static void send_response(const NetClientID *ptr = nullptr);
static void _setup_response();

int main() {
	_setup_response();

	std::cout << "choose either 's' for server or 'c' for client: ";
	char c = 0;
	std::cin >> c;

	c = tolower(c);

	NetCreateParams params = {};
	params.address.type = NetAddressType::eNAddrType_IPv4;
	params.address.port = 80;
	params.protocol = NetConnectionProtocol::eNConnectProto_TCP;

	if (c == 's')
	{
		std::cout << "starting server\n";

		NetServer server = {0};
		server.proc_client_recv = receive_data;
		server.proc_udp_recv = receive_data_udp;
		server.proc_client_left = client_left;
		server.proc_client_joined = client_joined;

		net_obj = &server;

		memset(params.address.name, 0, std::size(params.address.name));

		NetOpenServer(&server, &params);

		while (!close_requested && NetIsServerValid(&server))
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
		net_obj = &client;


		std::cout << "server address: ";
		std::string str{};
		std::cin >> str;


		strncpy(params.address.name, str.c_str(), std::size(params.address.name));

		params.address.port += 1;
		NetOpenClient(&client, &params);


		NetUserAddress user_address;
		user_address.port = params.address.port - 1;

		if (params.protocol == NetConnectionProtocol::eNConnectProto_UDP)
		{
			user_address.type = params.address.type;

			std::cout << "send udp address (* for the server address): ";
			std::cin >> str;

			if (str == "*")
			{
				strcpy_s(user_address.name, params.address.name);
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
				if (params.protocol == NetConnectionProtocol::eNConnectProto_TCP)
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

int client_joined(const NetClientID *client_id) {

	// send_response(client_id);
	// return client_joined_counter++;
	return 0;
}

void client_left(const NetClientID *client_id) {
	close_requested = true;
}

int receive_data(const NetClientID *client_id, NetPacketData data) {
	static constexpr std::array<char, 16> hex_arr = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
	};

	constexpr char close_key[] = "close";

	// std::cout << "received " << data.size << " bytes from " << &client_id->address << '\n';
	std::cout << "RECEIVED: " << data.size << " bytes from " << client_id->address.name << '\n';

	for (size_t i = 0; i < std::min<size_t>(data.size, 32); i++)
	{
		// std::cout << (hex_arr[data.data[i] >> 4]) << (hex_arr[data.data[i] & 0xf]);
		std::cout << (char)data.data[i];
	}

	std::cout << '\n';

	if (strncmp((const char *)data.data, close_key, std::size(close_key) - 1) == 0)
	{
		close_requested = true;
		std::cout << "closing!\n";
		return 0;
	}

	send_response();

	return 0;
}

void send_response(const NetClientID *ptr) {
	if (ptr == nullptr)
	{
		ptr = &((NetServer *)net_obj)->p_client_ids->client_id;
	}

	size_t length = strlen(response);
	// NetServerSend(&server, &server.p_client_ids->client_id, response, &length);
	NetServerSend((NetServer *)net_obj, ptr, response, &length);
}

void _setup_response() {
	const size_t size = 0xffff;
	char *const response_buf = new char[size + 1] {};
	char *current = response_buf;

	strcpy(current, response);
	current += strlen(current);

	FILE *fp = fopen("page.html", "r");

	if (fp == nullptr)
	{
		std::cout << "failed to load page\n";
		response = current;
		return;
	}

	size_t counter = fread(current, sizeof(char), size - (current - response_buf), fp);
	current[counter] = 0;

	response = response_buf;
	std::cout << "loaded page, bytes=" << counter << '\n';

	fclose(fp);
}
