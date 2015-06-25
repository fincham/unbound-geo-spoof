def init(id, cfg):
    return True

def deinit(id):
    return True

def inform_super(id, qstate, superqstate, qdata):
    return True

def get_remote_ip(qstate):
    reply_list = qstate.mesh_info.reply_list

    while reply_list:
        if reply_list.query_reply:
            return reply_list.query_reply.addr
        reply_list = reply_list.next

    return "0.0.0.0"

def operate(id, event, qstate, qdata):

    zones = [
        "hulu.com.",
        "huluim.com.",
        "netflix.com.",
        "netflix.net.",
        "ip2location.com.",
    ]
 
    spoofed_ip = '192.0.2.1'

    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
	remote_ip = get_remote_ip(qstate)

        if any([qstate.qinfo.qname_str.endswith(zone) for zone in zones]) and remote_ip != '127.0.0.1' and remote_ip != '0.0.0.0':
            msg = DNSMessage(qstate.qinfo.qname_str, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
            
            if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
                msg.answer.append("%s 10 IN A %s" % (qstate.qinfo.qname_str, spoofed_ip))
                log_info("geo_spoof: faking request %s for %s" % (qstate.qinfo.qname_str, remote_ip))

            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR 
                return True

            qstate.return_msg.rep.security = 2
            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED 
            return True
        else:
            log_info("geo_spoof: passthrough request %s for %s" % (qstate.qinfo.qname_str, remote_ip))
            qstate.ext_state[id] = MODULE_WAIT_MODULE 
            return True

    # when the 'iterator' is done doing real resolution
    if event == MODULE_EVENT_MODDONE:
        qstate.ext_state[id] = MODULE_FINISHED 
        return True
      
    # event is not handled
    qstate.ext_state[id] = MODULE_ERROR
    return True
