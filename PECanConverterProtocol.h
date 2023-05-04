//#pragma once
#ifndef PECANCONVERTERPROTOCOL_H
#define PECANCONVERTERPROTOCOL_H

#include <iostream>

#define STX 0xef
#define ETX 0xbe
#define PROTOCOL_START          STX
#define PROTOCOL_END            ETX

enum PACKET_TYPE
{
    PACKET_TYPE_UNKNOWN = 0,
    PACKET_TYPE_CAN_MESSAGE,
    PACKET_TYPE_PING,
    PACKET_TYPE_PING_ACK,
    PACKET_TYPE_ACK,
    PACKET_TYPE_ERROR_MESSAGE,
    PACKET_TYPE_CAN_MESSAGE_COLLECTION,
    PACKET_TYPE_CAN_ERROR_DATA,
    PACKET_TYPE_INVALID
};

uint32_t ProtocolCANUnpackID(uint8_t* writeBuffer);
uint8_t ProtocolCANUnpackRTR(uint8_t* writeBuffer);
uint32_t ProtocolCANUnpackDataLength(uint8_t* writeBuffer);

/*void ProtocolCANPackDataLength(uint8_t* pCANMessageBuffer, int length);
BYTE ProtocolCANUnpackDataLength(BYTE* pCANinputPacket);
void ProtocolCANPackId(uint8_t* pCANMessageBuffer, int nId);
void ProtocolCANPackRtr(BYTE* pCANMessageBuffer, BYTE rtr);
void ProtocolCANPackData(BYTE* pCANMessageBuffer, int nLength, BYTE* pData);*/

uint16_t ProtocolCalculateCRC(uint8_t* inputByte, uint8_t length);
#endif // !PECANCONVERTERPROTOCOL_H
