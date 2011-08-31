/*
 * nbee_link.cpp
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */


#include <string.h>
#include <nbee.h>
#include "nbee_link.h"


nbPacketDecoder *Decoder;
nbPacketDecoderVars* PacketDecoderVars;
nbNetPDLLinkLayer_t LinkLayerType;
nbPDMLReader *PDMLReader;
int PacketCounter= 1;
_nbPDMLPacket * curr_packet;
struct pcap_pkthdr * pkhdr;


extern "C" int initialize_nb_engine()
{

	char ErrBuf[ERRBUF_SIZE + 1];
	int NetPDLProtoDBFlags = nbPROTODB_FULL;
	int NetPDLDecoderFlags = nbDECODER_GENERATEPDML;
	int ShowNetworkNames = 0;

	char* NetPDLFileName = "/work/svnnetbee/bin/customnetpdl.xml";

	pkhdr = new struct pcap_pkthdr;

	if (nbIsInitialized() == nbFAILURE)
	{
		if (nbInitialize(NetPDLFileName, NetPDLProtoDBFlags, ErrBuf, sizeof(ErrBuf)) == nbFAILURE)
		{
			printf("Error initializing the NetBee Library; %s\n", ErrBuf);
			return nbFAILURE;
		}
	}

	Decoder= nbAllocatePacketDecoder(NetPDLDecoderFlags, ErrBuf, sizeof(ErrBuf));
	if (Decoder == NULL)
	{
		printf("Error creating the NetPDLParser: %s.\n", ErrBuf);
		return nbFAILURE;
	}

	// Get the PacketDecoderVars; let's do the check, although it is not really needed
	if ((PacketDecoderVars= Decoder->GetPacketDecoderVars()) == NULL)
	{
		printf("Error: cannot get an instance of the nbPacketDecoderVars class.\n");
		return nbFAILURE;
	}
	// Set the appropriate NetPDL configuration variables
//	PacketDecoderVars->SetVariableNumber((char*) NETPDL_VARIABLE_SHOWNETWORKNAMES, ShowNetworkNames);

	if (PacketDecoderVars->SetVariableNumber((char*) NETPDL_VARIABLE_SHOWNETWORKNAMES, ShowNetworkNames)==nbFAILURE)
	{
		printf("Error: cannot set variables of the decoder properly.\n");
		return nbFAILURE;
	}

	PDMLReader = Decoder->GetPDMLReader();

	return 0;

}

extern "C" int convertpkt_test(const unsigned char* pktin, list_t * pktout)
{
	printf("\nis it possible? 1");

	//pkhdr->ts.tv_sec = 0;
	pkhdr->caplen = 0; //need this information
	pkhdr->len = 0; //need this information

	// Decode packet
	if (Decoder->DecodePacket(LinkLayerType, PacketCounter, pkhdr, pktin) == nbFAILURE)
	{
		printf("\nError decoding a packet %s\n\n", Decoder->GetLastError());
		// Let's break and save what we've done so far
		return -1;
	}

	PDMLReader->GetCurrentPacket(&curr_packet);
	printf("\nis it possible? 2");

	_nbPDMLProto * proto;
	_nbPDMLField * field;

	proto = curr_packet->FirstProto;

	printf("\nPACKET LEN: %ld ",curr_packet->Length);

        pktout = (list_t*) malloc(sizeof(list_t));

	list_t_init(pktout);

	while (1)
	{
		printf("%s\n",*proto);
		field = proto->FirstField;
		while(1)
		{
			printf("\nfield position %ld,  %s :",field->Position,*field);
                        if(field->LongName[0]<58 && field->LongName[0]>47)
                        {
	                        int i,pow;

                                packet_out_t *new_field;
                                new_field = (packet_out_t *)malloc(sizeof(packet_out_t));
                                for (new_field->type=0,i=0,pow=100;i<3;i++,pow = (pow==1 ? pow : pow/10))
        	                        new_field->type = new_field->type + (pow*(field->LongName[i]-48));
                                new_field->length = field->Size;
                                printf("\n LongName: %d",new_field->type);
                                new_field->value = (uint8_t*) malloc(field->Size);
                                memcpy(new_field->value,(pktin + field->Position),field->Size);
                                list_t_push_back(pktout,&new_field->node);
                        }

			if(field->NextField == NULL && field->ParentField == NULL)
			{
				printf("\nbreaking");
				break;
			}
			else if (field->NextField == NULL && field->ParentField != NULL)
			{
				field = field->ParentField;
				printf("\nParent");
			}
			else if (!field->NextField->isField)
			{
				printf("\nblock : %s",*field->NextField);
				field = field->NextField->FirstChild;
			}
			else
			{
				printf("\n next field: %s ",*field->NextField);
				field = field->NextField;
			}

		}

		printf("\n");
		if (proto->NextProto == NULL)
		{
			break;
		}
		proto = proto->NextProto;
	}

	//printf("%s\n",*proto);
	printf("Packet %ld done\n",curr_packet->Number);

}
