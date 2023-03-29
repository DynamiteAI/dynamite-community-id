@ifdef (Files::Info)

module CommunityID;

export {
    redef record Files::Info += {
        community_id: string &optional &log;
    };
}

event file_state_remove(f: fa_file) &priority=10{
    if (f?$conns) {
        for ( key, value in f$conns ) {
            if ( value?$community_id  && f?$info) {
                f$info$community_id = value$community_id;
                break;
            }
        }
    }
}
@endif
