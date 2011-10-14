/*
 * nbee_link.cpp
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */


#include <string.h>
#include <nbee.h>
#include <netinet/in.h>

#include "nbee_link.h"
#include "../lib/bj_hash.h"
#include "../include/openflow/match-ext.h"


nbPacketDecoder *Decoder;
nbPacketDecoderVars* PacketDecoderVars;
nbNetPDLLinkLayer_t LinkLayerType;
nbPDMLReader *PDMLReader;
int PacketCounter= 1;
struct pcap_pkthdr * pkhdr;

static struct hmap all_packet_fields = HMAP_INITIALIZER(&all_packet_fields);

extern "C" int nbee_link_initialize()
{

	char ErrBuf[ERRBUF_SIZE + 1];
	int NetPDLProtoDBFlags = nbPROTODB_FULL;
	int NetPDLDecoderFlags = nbDECODER_GENERATEPDML_COMPLETE;
	int ShowNetworkNames = 0;

	char* NetPDLFileName = "customnetpdl.xml";

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

extern "C" int nbee_link_convertpkt(struct ofpbuf * pktin, struct hmap * pktout)
{
	//pkhdr->ts.tv_sec = 0;
	pkhdr->caplen = pktin->size; //need this information
	pkhdr->len = pktin->size; //need this information

	_nbPDMLPacket * curr_packet;

	// Decode packet
	if (Decoder->DecodePacket(LinkLayerType, PacketCounter, pkhdr, (const unsigned char*) (pktin->data)) == nbFAILURE)
	{
		printf("\nError decoding a packet %s\n\n", Decoder->GetLastError());
		// Let's break and save what we've done so far
		return -1;
	}

	PDMLReader->GetCurrentPacket(&curr_packet);

	_nbPDMLProto * proto;
	_nbPDMLField * field;

	proto = curr_packet->FirstProto;

	while (1)
        {
        	field = proto->FirstField;
              	while(1)
               	{
			
			if((char)field->LongName[0]<58 && (char)field->LongName[0]>47 && field->isField )
                        {
				/* A value between 47 and 58 indicates a field defined for Matching */
	                        int i,pow;
                                uint32_t type;
                                uint8_t size;
				packet_fields_t * pktout_field;
		                pktout_field = (packet_fields_t*) malloc(sizeof(packet_fields_t));


                                field_values_t *new_field;
                                new_field = (field_values_t *)malloc(sizeof(field_values_t));
				new_field->len = (uint32_t) field->Size;

                                for (type=0,i=0,pow=100;i<3;i++,pow = (pow==1 ? pow : pow/10))
        	                        type = type + (pow*(field->LongName[i]-48));
		                        
				size = field->Size;

                                pktout_field->header = NXM_HEADER(VENDOR_FROM_TYPE(type),FIELD_FROM_TYPE(type),size); 
                                new_field->value = (uint8_t*) malloc(field->Size);
                                memcpy(new_field->value,((uint8_t*)pktin->data + field->Position),field->Size);

				packet_fields_t *iter;
				bool done=0;
				HMAP_FOR_EACH(iter,packet_fields_t, hmap_node,pktout)
				{
					if(iter->header == pktout_field->header)
					{
						/* Adding entry to existing hash entry */
						list_t_push_back(&iter->fields,&new_field->list_node);
						done=1;
						break;
					}
				}

				if (!done)
				{
					/* Creating new hash map entry */
					list_t_init(&pktout_field->fields);
                                	list_t_push_back(&pktout_field->fields,&new_field->list_node);
                                	hmap_insert(pktout, &pktout_field->hmap_node,
	                        	hash_int(pktout_field->header, 0));
				}
				done =0;

			}

			if(field->NextField == NULL && field->ParentField == NULL) 
			{
				/* Protocol Done */
				break;
			}
			else if (field->NextField == NULL && field->ParentField != NULL)
			{
				field = field->ParentField;
			}
			else if (!field->NextField->isField)
			{

				if ((char)field->NextField->LongName[0]<58 && (char)field->NextField->LongName[0]>47)
				{
		                        int i,pow;
	                                uint32_t type;
					packet_fields_t * pktout_field;
			                pktout_field = (packet_fields_t*) malloc(sizeof(packet_fields_t));

		                        field_values_t *new_field;
                	                new_field = (field_values_t *)malloc(sizeof(field_values_t));

					for (type=0,i=0,pow=100;i<3;i++,pow = (pow==1 ? pow : pow/10))
        	                        	type = type + (pow*(field->NextField->LongName[i]-48));
								
				        new_field->value = (uint8_t*) malloc(field->Size);
					_nbPDMLField * nbPrevField; 
				
					if( !field->isField)
						nbPrevField = field->FirstChild;
					else
						nbPrevField = proto->FirstField;

					string NextHeader ("nexthdr");
					bool found = true;
					while(NextHeader.compare(nbPrevField->Name))
					{
						if(nbPrevField->NextField != NULL)
							nbPrevField=nbPrevField->NextField;
						else
						{
							found = false ;
							break;
						}
					}

					if (found)
					{
                                		pktout_field->header = NXM_HEADER(VENDOR_FROM_TYPE(type),FIELD_FROM_TYPE(type),nbPrevField->Size);
	                                	memcpy(new_field->value,((uint8_t*)pktin->data + nbPrevField->Position),nbPrevField->Size);	
						new_field->len = (uint32_t) nbPrevField->Size;

						packet_fields_t *iter;
						bool done=0;
						HMAP_FOR_EACH(iter,packet_fields_t, hmap_node,pktout)
						{
							if(iter->header == pktout_field->header)
							{
								/* Adding entry to existing hash entry */
								done=1;
								break;
							}
						}
	
						if (!done)
						{
							/* Creating new hash map entry */
							list_t_init(&pktout_field->fields);
		                                	list_t_push_back(&pktout_field->fields,&new_field->list_node);
		                                	hmap_insert(pktout, &pktout_field->hmap_node,
			                        	hash_int(pktout_field->header, 0));
						}
					}
				}
				/* Next field is a block. */
				field = field->NextField->FirstChild;
			}
			else
			{
				field = field->NextField;
			}

		}

		if (proto->NextProto == NULL) 
		{
			/* Packet Done */
			break;
		}
		proto = proto->NextProto;
	}

/*	PacketCounter++;
	if(PacketCounter == 10)
		PacketCounter = 1;
*/
	packet_fields_t *fields;

	HMAP_FOR_EACH (fields,packet_fields_t, hmap_node,pktout){
		if(fields != NULL)
		{
			printf("\nfield: %d    | size: %d     | ",fields->header,NXM_LENGTH(fields->header));
			field_values_t *iter;
			int count=0;
			LIST_T_FOR_EACH(iter, field_values_t, list_node, &fields->fields)
			{
				printf("size on len: %d",iter->len);
		                int x;
				printf("\n%d          ",count);
				count++;
				
       			        for (x=0;x<NXM_LENGTH(fields->header);x++)
                		{
					printf("%02X",iter->value[x]);
                		}
			}
		}
	}
	return 1;
}

