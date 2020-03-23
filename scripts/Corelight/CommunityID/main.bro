# Bro package & plugin for adding community hash IDs to conn.log.
# This is loaded when a user activates the plugin.
#
module CommunityID;

export {
    # An unsigned 16-bit number to seed our hashing
    const seed: count = 0 &redef;

    # Whether to add a base64 pass over the hash digest.
    # Enabled by default, since it shortens the output.
    const do_base64: bool = T &redef;

    # Verbose debugging log output to the console.
    const verbose: bool = F &redef;

    # Add the ID string field to the connection record, for reuse
    # during its lifespan
    redef record connection += {
        community_id: string &optional;
    };

    # Add the ID to the conn record 
    redef record Conn::Info += {
        community_id: string &optional &log;
    };

    # Add the ID to the http record 
    redef record HTTP::Info += {
        community_id: string &optional &log;
    };    
    # Add the ID to the DNS record 
    redef record DNS::Info += {
        community_id: string &optional &log;
    };    
    # Add the ID to the SSH record 
    redef record SSH::Info += {
        community_id: string &optional &log;
    };    
    # Add the ID to the SSL record 
    redef record SSL::Info += {
        community_id: string &optional &log;
    };    

    # Add the ID to the SIP record 
    redef record SIP::Info += {
        community_id: string &optional &log;
    };    
}


# For successful conns, add the ID early in the lifecycle
# so we can populate the ID in app-layer logs
event connection_established(c: connection) 
    {
    c$community_id = hash_conn(c);
    }

# Add the ID to the conn log. if the connection wasn't successful
# the ID will be calculated and added now.  
event connection_state_remove(c: connection) 
    {
    if (c?$community_id) 
        c$conn$community_id = c$community_id;
    else 
        c$conn$community_id = hash_conn(c);
    }

# Add the ID to app-layer records. Do this on the first available event fired
# where the relevant *::Info record field has been initialized in the connection
# record.  Handling the *_request events for each analyzer ensures requests with 
# no reply will still have a populated community_id field. 
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if (c?$community_id)
        c$http$community_id = c$community_id;
    }

# No connection_established events for UDP so need to force this for DNS queries 
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    # new_connection is not being triggered for UDP, so we need another plan 
    if (c?$community_id)
        c$dns$community_id = c$community_id;
    else
	{ 
        c$community_id = hash_conn(c);	
        c$dns$community_id = c$community_id;	
	}
    }

event ssh_client_version(c: connection , version: string )
    {
    if (c?$community_id)
        c$ssh$community_id = c$community_id;
    }

event sip_request(c: connection , method: string , original_URI: string , version: string ) 
    {
    if (c?$community_id)
        c$sip$community_id = c$community_id;
    }

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec)
    {
    if (c?$community_id)
        c$ssl$community_id = c$community_id;
    }
