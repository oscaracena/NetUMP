/*
 *  NetUMP_SessionProtocol.cpp
 *  Generic class for NetUMP session initiator/listener
 *  Methods for session management
 *
 * Copyright (c) 2023 Benoit BOUCHEZ / KissBox
 * License : MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "NetUMP.h"

void CNetUMPHandler::SendInvitationCommand (void)
{
	TUMP_INVITATION_PACKET InvitationPacket;
	sockaddr_in AdrEmit;
	size_t WordLen;
	size_t NameLen = strlen ((char*)&this->EndpointName[0]);
	size_t PIDLen = strlen((char*)&this->ProductInstanceID[0]);

	// NetUMP specification requires that all stuffing bytes in the packet must be filled with 0
	memset(&InvitationPacket.EPName_PIID[0], 0, MAX_UMP_ENDPOINT_NAME_LEN + MAX_UMP_PRODUCT_INSTANCE_ID_LEN);

	// Compute size in words of Endpoint Name
	NameLen+=1;					// Add null terminator
	WordLen = NameLen>>2;		// Get count of int32 words
	if ((NameLen&0x3)!=0)
		WordLen+=1;		// Add one extra word if length is not a multiple of four
	InvitationPacket.CSD1 = (uint8_t)WordLen;

	// Add size in words of ProductID
	PIDLen += 1;
	WordLen += PIDLen >> 2;
	if ((PIDLen & 0x03) != 0)
		WordLen += 1;
	InvitationPacket.PayloadLength = (uint8_t)WordLen;

	InvitationPacket.Signature = htonl (UMP_SIGNATURE);
	InvitationPacket.CommandCode = INVITATION_COMMAND;
	InvitationPacket.CSD2 = 0;			// Bitmap = 0 : no authentication capabilities

	// Copy Endpoint Name at the beginning of the string
	strcpy ((char*)&InvitationPacket.EPName_PIID[0], (char*)&this->EndpointName[0]);
	// Add Product Instance ID at first word after the Endpoint Name
	strcpy((char*)&InvitationPacket.EPName_PIID[InvitationPacket.CSD1 * 4], (char*)&this->ProductInstanceID[0]);

	memset (&AdrEmit, 0, sizeof(sockaddr_in));
	AdrEmit.sin_family=AF_INET;
	AdrEmit.sin_addr.s_addr=htonl(SessionPartnerIP);
	AdrEmit.sin_port=htons(RemoteUDPPort);
	sendto(UMPSocket, (const char*)&InvitationPacket, 8+((int)WordLen*4), 0, (const sockaddr*)&AdrEmit, sizeof(sockaddr_in));
}  // CNetUMPHandler::SendInvitationCommand
//---------------------------------------------------------------------------

void CNetUMPHandler::SendInvitationAcceptedCommand (void)
{
	TUMP_INVITATION_ACCEPTED_PACKET ReplyPacket;
	sockaddr_in AdrEmit;
	size_t NameLen = strlen((char*)&this->EndpointName[0]);
    size_t PIDLen = strlen((char*)&this->ProductInstanceID[0]);
	size_t WordLen = 0;

	// NetUMP specification requires that all stuffing bytes in the packet must be filled with 0
	memset(&ReplyPacket.EPName_PIID[0], 0, MAX_UMP_ENDPOINT_NAME_LEN + MAX_UMP_PRODUCT_INSTANCE_ID_LEN);

	// Compute size in words of Endpoint Name
	NameLen+=1;					// Add null terminator
	WordLen = NameLen>>2;		// Get count of int32 words
	if ((NameLen&0x3)!=0)
		WordLen+=1;		// Add one extra word if length is not a multiple of four
	ReplyPacket.CSD1 = (uint8_t)WordLen;

	// Add size in words of ProductID
	PIDLen += 1;
	WordLen += PIDLen >> 2;
	if ((PIDLen & 0x03) != 0)
		WordLen += 1;
	ReplyPacket.PayloadLength = (uint8_t)WordLen;

	ReplyPacket.Signature = htonl (UMP_SIGNATURE);
	ReplyPacket.CommandCode = INVITATION_ACCEPTED_COMMAND;
	ReplyPacket.CSD2 = 0;

	// Copy Endpoint Name at the beginning of the string
	strcpy ((char*)&ReplyPacket.EPName_PIID[0], (char*)&this->EndpointName[0]);
	// Add Product Instance ID at first word after the Endpoint Name
	strcpy((char*)&ReplyPacket.EPName_PIID[ReplyPacket.CSD1 * 4], (char*)&this->ProductInstanceID[0]);

	memset (&AdrEmit, 0, sizeof(sockaddr_in));
	AdrEmit.sin_family=AF_INET;
	AdrEmit.sin_addr.s_addr=htonl(SessionPartnerIP);
	AdrEmit.sin_port=htons(SessionPartnerPort);
	sendto(UMPSocket, (const char*)&ReplyPacket, 8 + ((int)WordLen * 4), 0, (const sockaddr*)&AdrEmit, sizeof(sockaddr_in));
}  // CNetUMPHandler::SendInvitationAcceptedCommand
//---------------------------------------------------------------------------

void CNetUMPHandler::SendBYECommand (unsigned char BYEReason, unsigned int DestinationIP, unsigned short DestinationPort)
{
	TUMP_BYE_PACKET PacketBYE;
	sockaddr_in AdrEmit;

	PacketBYE.Signature = htonl (UMP_SIGNATURE);
	PacketBYE.CommandCode = BYE_COMMAND;
	PacketBYE.PayloadLength = 0;
	PacketBYE.BYECode = BYEReason;
	PacketBYE.Reserved = 0;

	memset (&AdrEmit, 0, sizeof(sockaddr_in));
	AdrEmit.sin_family=AF_INET;
	AdrEmit.sin_addr.s_addr=htonl(DestinationIP);
	AdrEmit.sin_port=htons(DestinationPort);
	sendto(UMPSocket, (const char*)&PacketBYE, sizeof(TUMP_BYE_PACKET), 0, (const sockaddr*)&AdrEmit, sizeof(sockaddr_in));
} // CNetUMPHandler::SendBYECommand
//---------------------------------------------------------------------------

void CNetUMPHandler::SendBYEReplyCommand (unsigned int DestinationIP, unsigned short DestinationPort)
{
	TUMP_BYE_REPLY_PACKET PacketReply;
	sockaddr_in AdrEmit;

	PacketReply.Signature = htonl (UMP_SIGNATURE);
	PacketReply.CommandCode = BYE_REPLY_COMMAND;
	PacketReply.PayloadLength = 0;
	PacketReply.Reserved = 0;

	memset (&AdrEmit, 0, sizeof(sockaddr_in));
	AdrEmit.sin_family=AF_INET;
	AdrEmit.sin_addr.s_addr=htonl(DestinationIP);
	AdrEmit.sin_port=htons(DestinationPort);
	sendto(UMPSocket, (const char*)&PacketReply, sizeof(TUMP_BYE_REPLY_PACKET), 0, (const sockaddr*)&AdrEmit, sizeof(sockaddr_in));
}  // CNetUMPHandler::SendBYEReplyCommand
//---------------------------------------------------------------------------

void CNetUMPHandler::SendPINGCommand (uint32_t PINGId)
{
	TUMP_PING_PACKET PingPacket;
	sockaddr_in AdrEmit;

	PingPacket.Signature = htonl (UMP_SIGNATURE);
	PingPacket.CommandCode = PING_COMMAND;
	PingPacket.PayloadLength = 1;
	//PingPacket.SequenceNumber = htons (LastCommandCounter);
	PingPacket.Reserved = 0;
	PingPacket.ID = htonl (PINGId);

	memset (&AdrEmit, 0, sizeof(sockaddr_in));
	AdrEmit.sin_family=AF_INET;
	AdrEmit.sin_addr.s_addr=htonl(SessionPartnerIP);
	AdrEmit.sin_port=htons(SessionPartnerPort);
	sendto(UMPSocket, (const char*)&PingPacket, sizeof(TUMP_PING_PACKET), 0, (const sockaddr*)&AdrEmit, sizeof(sockaddr_in));
}  // CNetUMPHandler::SendPINGCommand
//---------------------------------------------------------------------------

void CNetUMPHandler::SendPINGReplyCommand (uint32_t PINGId)
{
	TUMP_PING_REPLY_PACKET ReplyPacket;
	sockaddr_in AdrEmit;

	ReplyPacket.Signature = htonl (UMP_SIGNATURE);
	ReplyPacket.CommandCode = PING_REPLY_COMMAND;
	ReplyPacket.PayloadLength = 1;
	//ReplyPacket.SequenceNumber = htons (UMPCommandCounter);
	ReplyPacket.Reserved = 0;
	ReplyPacket.ID = htonl (PINGId);

	memset (&AdrEmit, 0, sizeof(sockaddr_in));
	AdrEmit.sin_family=AF_INET;
	AdrEmit.sin_addr.s_addr=htonl(SessionPartnerIP);
	AdrEmit.sin_port=htons(SessionPartnerPort);
	sendto(UMPSocket, (const char*)&ReplyPacket, sizeof(TUMP_PING_REPLY_PACKET), 0, (const sockaddr*)&AdrEmit, sizeof(sockaddr_in));
}  // CNetUMPHandler::SendPINGReplyCommand
//---------------------------------------------------------------------------
