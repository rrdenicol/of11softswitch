#include "packet_handle_ext.h"
#include "openflow/match-ext.h"

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

void
packet_handle_ext_validate(struct packet_handle_ext *handle) {

	if(handle->valid)
		return;

	int ret =0;
	ret = nbee_link_convertpkt(handle->pkt->buffer,&handle->fields);
	if (!(ret<0) )
		handle->valid = true;

	packet_fields_t * in_port;
	in_port = (packet_fields_t*) malloc(sizeof(packet_fields_t));
	in_port->header = TLV_EXT_IN_PORT;
				
        field_values_t *new_field;
        new_field = (field_values_t *)malloc(sizeof(field_values_t));
	new_field->value = (uint8_t*) malloc(NXM_LENGTH(TLV_EXT_IN_PORT));
        memcpy(new_field->value,((uint8_t*)&handle->pkt->in_port),NXM_LENGTH(TLV_EXT_IN_PORT));
	
	list_t_init(&in_port->fields);
        list_t_push_back(&in_port->fields,&new_field->list_node);
        hmap_insert(&handle->fields, &in_port->hmap_node,
	hash_int(in_port->header, 0));

	return ret;

}
