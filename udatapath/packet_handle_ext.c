#include "packet_handle_ext.h"

/* Creates a handler */
struct packet_handle_ext *
packet_handle_ext_create(struct packet *pkt) {
	struct packet_handle_ext *handle = xmalloc(sizeof(struct packet_handle_ext));

	handle->pkt = pkt;
	hmap_init(handle->fields);
	handle->valid = false;

	packet_handle_ext_validate(handle);

	return handle;
}

void
packet_handle_ext_validate(struct packet_handle_ext *handle) {

	if(handle->valid)
		return;

	int ret =0;
	ret = nbee_link_convertpkt(handle->pkt,handle->fields);

	return ret;

}
