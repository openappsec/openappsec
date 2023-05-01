#ifndef __MOCK_SOCKET_IS_H__
#define __MOCK_SOCKET_IS_H__

#include "i_socket_is.h"
#include "cptest.h"
#include "common.h"

std::ostream & operator<<(std::ostream &os, const Maybe<std::vector<char>> &) { return os; }

class MockSocketIS : public Singleton::Provide<I_Socket>::From<MockProvider<I_Socket>>
{
public:
    MOCK_METHOD4(genSocket, Maybe<socketFd> (SocketType, bool, bool, const std::string &));
    MOCK_METHOD3(acceptSocket, Maybe<socketFd> (socketFd, bool, const std::string &authorized_ip));
    MOCK_METHOD1(closeSocket, void (socketFd &));
    MOCK_METHOD1(isDataAvailable, bool (socketFd));
    MOCK_METHOD2(writeData, bool (socketFd, const std::vector<char> &));
    MOCK_METHOD3(receiveData, Maybe<std::vector<char>> (socketFd, uint, bool is_blocking));
};

#endif // __MOCK_SOCKET_IS_H__
