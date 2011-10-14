#include "packet_handle_ext.h"
#include "match-ext.h"
#include "match_ext.h"
#include "lib/bj_hash.h"
#include "lib/hmap.h"

/* Creates a handler */
struct packet_handle_ext *
packet_handle_ext_create(struct packet *pkt) {
	struct packet_handle_ext *handle = xmalloc(sizeof(struct packet_handle_ext));
	handle->pkt = pkt;
	hmap_init(&handle->fields);
	
	handle->valid = false;
	packet_handle_ext_validate(handle);

	return handle;
}

int
packet_handle_ext_validate(struct packet_handle_ext *handle) {

    int ret;
	if(handle->valid)
		return 0;

	ret = 0;
	ret = nbee_link_convertpkt(handle->pkt->buffer,&handle->fields);
    
    /* Add in_port value to the hash_map */
     
    packet_fields_t * pktout_field;
	pktout_field = (packet_fields_t*) malloc(sizeof(packet_fields_t));
	
	pktout_field->header = TLV_EXT_IN_PORT;
    field_values_t *new_field;
    new_field = (field_values_t *)malloc(sizeof(field_values_t));

    new_field->len = sizeof(uint32_t);
    new_field->value = (uint8_t*) malloc(sizeof(uint32_t));
    memset(new_field->value,0x0,sizeof(uint32_t));
    memcpy(new_field->value,&handle->pkt->in_port,sizeof(uint32_t));
    list_t_init(&pktout_field->fields);
    list_t_push_back(&pktout_field->fields,&new_field->list_node);
    hmap_insert(&handle->fields, &pktout_field->hmap_node,hash_int(pktout_field->header, 0));
   
    if (ret > -1)
        handle->valid = true;
	return ret;

}

bool
packet_handle_ext_match(struct packet_handle_ext *handle, struct flow_hmap *match){
    
    int val = packet_handle_ext_validate(handle);
    if (val < 0){ 
        printf("Don't Match \n");
        return false;
        
    }
    bool teste = packet_match(&match->flow_fields,&handle->fields );
    return teste;

}
