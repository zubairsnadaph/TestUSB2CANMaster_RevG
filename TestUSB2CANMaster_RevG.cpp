// TestUSB2CANMaster_RevG.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <winreg.h>
#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include "PECanConverterProtocol.h"

#define MAX_CAN_MESSAGE_LENGTH	20

HANDLE h_Serial;

LONG GetStringRegKey(HKEY hKey, const std::wstring &strValueName, std::wstring &strValue, const std::wstring &strDefaultValue)
{
    strValue = strDefaultValue;
    WCHAR szBuffer[512];
    DWORD dwBufferSize = sizeof(szBuffer);
    ULONG nError;
    nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
    if (ERROR_SUCCESS == nError)
    {
        strValue = szBuffer;
    }
    return nError;
}

bool connectToCOMM(void)
{
    bool COMMstat = true;

    HKEY hKey;
    LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\SERIALCOMM", 0, KEY_READ, &hKey);   

    std::wstring strValueOfComPort;

    GetStringRegKey(hKey, L"\\Device\\VCP0", strValueOfComPort, L"bad");

    /*uint8_t comPort[10] = "COM6";
    comPort[3] = (uint8_t)strValueOfComPort.at(3);
    //memcpy(comPort, strValueOfComPort.c_str(), 10);

    //strValueOfComPort.copy((wchar_t*)comPort, 5);

    //std::cout << "\nOpening " << comPort << "\n";*/

    h_Serial = CreateFile(strValueOfComPort.c_str(), GENERIC_READ | GENERIC_WRITE,
        0,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0);

    if (h_Serial == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            //serial port not found. Handle error here.
            std::cout << "Serial port not found\n";
        }
        //any other error. Handle error here.
        //std::cout << "Invalid Handle!\n";
        return NULL;
    }
    else // update message of successful connection
    {
        std::cout << "RS232 active\n";
    }

    DCB dcbSerialParam = { 0 };
    dcbSerialParam.DCBlength = sizeof(dcbSerialParam);

    if (!GetCommState(h_Serial, &dcbSerialParam)) {
        //handle error here
        std::cout << "Unable to get Comm state\n";
        return NULL;
    }

    dcbSerialParam.BaudRate = CBR_115200;
    dcbSerialParam.ByteSize = 8;
    dcbSerialParam.StopBits = ONESTOPBIT;
    dcbSerialParam.Parity = NOPARITY;

    if (!SetCommState(h_Serial, &dcbSerialParam)) {
        //handle error here
        std::cout << "Unable to set Comm state\n";
        return NULL;
    }

    COMMTIMEOUTS timeout = { 0 };
    timeout.ReadIntervalTimeout = 60;
    timeout.ReadTotalTimeoutConstant = 500;
    timeout.ReadTotalTimeoutMultiplier = 15;
    timeout.WriteTotalTimeoutConstant = 60;
    timeout.WriteTotalTimeoutMultiplier = 8;
    if (!SetCommTimeouts(h_Serial, &timeout)) {
        //handle error here
        std::cout << "Unable to set Comm timeouts\n";
        return NULL;
    }

    return COMMstat;
}

bool WriteCOMMport(uint8_t* buffer, uint8_t writeSize)
{
    bool writeStatus = true;
    DWORD dwRead = 0;

    if (!WriteFile(h_Serial, buffer, writeSize, &dwRead, NULL)) {
        //handle error here
        std::cout << "Unable to write to the Comm port\n";
        CloseHandle(h_Serial); // free the COM port
        writeStatus = false;
    }

    return writeStatus;
}

bool ReadCOMMport(uint8_t* buffer, uint8_t readSize)
{
    bool readStatus = true;
    DWORD dwRead = 0;

    if (!ReadFile(h_Serial, buffer, readSize, &dwRead, NULL)) {
        //handle error here
        std::cout << "Unable to read from the Comm port\n";
        CloseHandle(h_Serial); // free the COM port
        readStatus = false;
    }

    return readStatus;
}

void ProtocolSendAck(void)
{
    static uint8_t writeBuffer[3] = { 0xEF,0x04,0xBE };
    DWORD dwRead = 0;

    if (!WriteFile(h_Serial, writeBuffer, 3, &dwRead, NULL)) {
        //handle error here
        std::cout << "Unable to write to the Comm port\n";
        CloseHandle(h_Serial); // free the COM port
    }
}

int main()
{
	uint8_t data[8];
	uint8_t sizeofUSBbuf = 0;
	uint8_t canMessage[MAX_CAN_MESSAGE_LENGTH] = {0xEF};
    uint8_t readBuff[MAX_CAN_MESSAGE_LENGTH] = {};
	uint16_t crcCalculate = 0;
    uint32_t ackCount = 0;
    uint8_t transmissionCntr = 0;

    if (connectToCOMM())
    {
        while (true)
        {
            // Running as the master, so send out CAN messages
            for (int i = 0; i < 247; i++)
            {
                for (int j = 0; j < 9; j++)
                {
                    for (int k = 0; k < j; k++)
                    {
                        data[k] = (i & 0xff) + k;
                    }
                    uint8_t dataLength = j;

                    ZeroMemory(canMessage, sizeof(canMessage)); // reset the CAN bufferProtocolCANPackInitialize(canMessage);

                    canMessage[0] = STX;
                    canMessage[1] = PACKET_TYPE_CAN_MESSAGE_COLLECTION;
                    canMessage[3] = (dataLength) << 4; // higher nibble is length or with msb of id
                    canMessage[3] |= ((i & 0xff00) >> 8);
                    canMessage[4] = i & 0xff; // remaining bytes of id
                    canMessage[3] |= 0 << 3; // RTR bit which is always 0 for tester

                    memcpy((uint8_t*)(canMessage + 5), data, dataLength);

                    sizeofUSBbuf = 3 + dataLength; // 3 additional : 2 for dlc/id-rtrx, 1 for size of CAN burst

                    canMessage[2] = sizeofUSBbuf;

                    crcCalculate = ProtocolCalculateCRC((uint8_t*)(canMessage + 2), canMessage[2]);
                    canMessage[sizeofUSBbuf + 5 - 3] = (crcCalculate & 0x00FF); // +5 for STX, type, CRC1, CRC2, ETX; -3 is the index from last
                    canMessage[sizeofUSBbuf + 5 - 2] = (crcCalculate & 0xFF00) >> 8; // +5 for STX, type, CRC1, CRC2, ETX; -3 is the index from last
                    canMessage[sizeofUSBbuf + 5 - 1] = ETX; // +5 for STX, type, CRC1, CRC2, ETX; -3 is the index from last

                    if (transmissionCntr)
                    {
                        std::cout << "CAN bus unavailable transmission stopped\n";
                        while (1); // stop sending/receiving message if unable to do it up to 3 times
                    }

                    if (!WriteCOMMport(canMessage, canMessage[2] + 5)) //+5 for STX, MSG-Type, CRC1, CRC2, ETX
                    {
                        while(1); // the error message is displayed in the write function call so no need here
                    }

                    while (readBuff[1] == 0) // keep looking for ACK by the board to the sent USB-CAN packet
                    {
                        ReadCOMMport(readBuff, 3);
                    }

                    if (readBuff[0] == STX && readBuff[1] == PACKET_TYPE_ACK && readBuff[2] == ETX)
                    {
                        ackCount++;
                        std::cout << "ackCount: " << ackCount << "\n";
                        ZeroMemory(readBuff, sizeof(readBuff)); // reset the read buffer for next iteration

                        Sleep(50); // wait for 50ms for the board on the other side to respond with any error

                        if (ReadCOMMport(readBuff, canMessage[2] + 5)) // read error(can/winprep-protocol) followed with ACK message
                        {
                            switch (readBuff[1])
                            {
                            case 0: // no error-data received
                                break;

                            case PACKET_TYPE_ERROR_MESSAGE:
                                std::cout << "Transmission error\n";
                                transmissionCntr++;
                                break;

                            default:
                                std::cout << "Non-protocol standard CAN message\n";
                                break;
                            }
                        }
                    }
                    /*if (ReadCOMMport(readBuff, 3)) // read ACK/error from USB2CAN on writing CAN message request
                    {
                        if (readBuff[0] == STX && readBuff[1] == PACKET_TYPE_ACK && readBuff[2] == ETX)
                        {
                            ackCount++;
                            std::cout << "ackCount: " << ackCount << "\n";
                            ZeroMemory(canMessage, sizeof(canMessage)); // reset the read buffer for next iteration

                            if (ReadCOMMport(readBuff, canMessage[2] + 5)) // read can/error(can/protocol) followed with ACK message
                            {
                                switch (readBuff[1])
                                {
                                case PACKET_TYPE_PING:
                                    break;

                                case PACKET_TYPE_ERROR_MESSAGE:
                                    std::cout << "Transmission error\n";
                                    break;

                                case PACKET_TYPE_CAN_MESSAGE:
                                    sizeofUSBbuf = 4 + ProtocolCANUnpackDataLength(readBuff + 2);
                                    crcCalculate = ProtocolCalculateCRC((uint8_t*)(canMessage + 2), canMessage[2]);
                                    if (((uint16_t)readBuff[sizeofUSBbuf + 1] << 8U | readBuff[sizeofUSBbuf]) != crcCalculate) // CRC error
                                    {
                                        std::cout << "CRC error\n";
                                        break;
                                    }
                                    ProtocolSendAck(); //Acknowledge to USB2CAN that the sensor data is received
                                    break;

                                default:
                                    std::cout << "Non-protocol standard CAN message\n";
                                    break;
                                }
                            }
                            else
                            {
                                while (1); // stay here indefinitely
                            }
                        }
                    }
                    else
                    {
                        while (1);
                    }*/
                    Sleep(50);
                }
            }
        }
    }
    else
    {
        while (1);
    }

	
	return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
