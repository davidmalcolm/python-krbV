# Here are some snippets of code from an application of mine that 
# uses the krbV module
import krbV

class AuthManager:
    def __init__(self, app, cache_file=None, primary_principal=None, keytab=None):
        self.context = krbV.default_context()
        self.primary_principal = primary_principal
        self.keytab = keytab
        if not keytab:
            self.keytab = app.config.get('auth.keytab')
        if self.keytab and not isinstance(self.keytab, krbV.Keytab):
            self.keytab = krbV.Keytab(name=self.keytab, context=self.context)
        if not self.primary_principal:
            self.primary_principal = app.config.get('auth.principal')
        if not self.primary_principal:
            self.primary_principal = None
        if self.primary_principal and not isinstance(self.primary_principal, krbV.Principal):
            self.primary_principal = krbV.Principal(name=self.primary_principal, context=self.context)
        if self.primary_principal:
            if cache_file:
                self.ccache = krbV.CCache(name="FILE:"+cache_file, context=self.context,
                                          primary_principal=self.primary_principal)
            else:
                self.ccache = self.context.default_ccache(primary_principal=self.primary_principal)
        else:
            if cache_file:
                self.ccache = krbV.CCache(name="FILE:"+cache_file, context=self.context)
            else:
                self.ccache = self.context.default_ccache()
            self.primary_principal = self.ccache.principal()
        if self.keytab: self.reinit()
        self.local_rsa_info = None
        self.rsa_info = {}

    def reinit(self):
        assert self.keytab
        assert self.primary_principal
        self.app.log("Reinitializing Kerberos credentials", level='debug', local=1)
        # Apparently, wiping the ccache is required
        self.ccache.init(self.primary_principal)
        self.ccache.init_creds_keytab(keytab=self.keytab, principal=self.primary_principal)

# In the below functions, authmgr is an instance of the above class, if that helps at all.

class ConnectionInitiator:
    def finish_state(self):
        if self.state == self.STATE_SETUP:
            need_retry = 10
            authmgr = self.cnx.coord.app.auth
            while need_retry:
	        need_retry -= 1
                try:
                    princ = authmgr.primary_principal
                    creds = (princ, krbV.Principal('krbtgt/%s@%s' % (princ.realm, princ.realm), context=authmgr.context),
                             (0, None), (0,0,0,0), None, None, None, None,
                             None, None)
                    ocreds = authmgr.ccache.get_credentials(creds)
                    need_retry = 0
                except krbV.Krb5Error, e:
		    if not need_retry: raise
                    if e.err_code != krbV.KRB5KRB_AP_ERR_TKT_EXPIRED:
                        return self.fail()
                    authmgr.reinit()
            self.write_vals = {'localname':self.cnx.coord.app.localname, 'cnxid':self.cnx.cnxid,
                               'localprinc':princ.name, 'reqdata':ocreds[7],
                               'useruserkey':ocreds[2]}
            self.state = self.STATE_WRITING
        elif self.state == self.STATE_WRITING:
            self.state = self.STATE_READING
        elif self.state == self.STATE_READING:
            ac = None
            res = None
            need_retry = 1
            authmgr = self.cnx.coord.app.auth
            while need_retry:
                try:
                    ac = krbV.AuthContext(context=authmgr.context)
                    ac.flags = krbV.KRB5_AUTH_CONTEXT_DO_SEQUENCE
                    ac.useruserkey = self.write_vals['useruserkey']
                    res = authmgr.context.rd_req(self.read_vals['reqdata'], auth_context=ac, server=authmgr.primary_principal)
                    need_retry = 0
                except krbV.Krb5Error, e:
		    if e.err_code != krbV.KRB5KRB_AP_ERR_TKT_EXPIRED:
			    return self.fail("Kerberos error %s/%s" % (e.err_code, e.message))
                    authmgr.reinit()
            ac.genaddrs(self.cnxsock,
                        flags=krbV.KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR|krbV.KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR)
            self.read_vals['ac'] = ac
            assert len(res) == 4, res
            assert res[3][2] != self.coord.app.auth.primary_principal, res
            self.read_vals['user'] = res[3][2].name
            self.state = self.STATE_DONE
            self.cnx.initiated = 1

class ConnectionAcceptor:
    def finish_state(self):
        if self.state == self.STATE_SETUP:
            self.state = self.STATE_READING
        elif self.state == self.STATE_READING:
            authmgr = self.coord.app.auth
            remprinc = self.read_vals['remprinc']
            creds = (authmgr.primary_principal, krbV.Principal(remprinc, context=authmgr.context),
                     (0, None), (0,0,0,0), None, None, None, None,
                     self.read_vals['reqdata'], None)
            ac = None
            req = None
            need_retry = 10
            while need_retry:
	        need_retry -= 1
                try:
                    ocreds = authmgr.ccache.get_credentials(creds, options=krbV.KRB5_GC_USER_USER)
                    ac = krbV.AuthContext(context=authmgr.context)
                    ac.flags = krbV.KRB5_AUTH_CONTEXT_DO_SEQUENCE
                    opts=krbV.AP_OPTS_USE_SESSION_KEY|krbV.AP_OPTS_MUTUAL_REQUIRED
                    req = authmgr.context.mk_req(options=opts, creds=ocreds, auth_context=ac, ccache=authmgr.ccache)
                    need_retry = 0
                except krbV.Krb5Error, e:
		    if not need_retry: raise
                    if e.err_code != krbV.KRB5KRB_AP_ERR_TKT_EXPIRED:
                        raise
                    authmgr.reinit()
            ourid = None
            if self.idmap.has_key(self.read_vals['remid']):
                ourid = self.idmap[self.read_vals['remid']]
                assert type(ourid) in (tuple, list)
                self.cnx = ourid[1]
                self.cnx.cnxid = ourid[0]
                ourid = ourid[0]
            else:
                for I in self.coord.all_cnxs:
                    if I.cnxaddr and socket.gethostbyname(I.cnxaddr[0]) == socket.gethostbyname(self.addr[0]) and I.name == self.read_vals['remname']:
                        if I.cnx_state == I.CNX_CONNECTED:
                            # If we have an outgoing connection with the same info, we just drop this incoming one on the floor.
                            self.coord.log('Dropping incoming connection from %s because it matches outgoing connection %#x',
                                           self.addr, id(I), level='debug', local=1)
                            return self.fail()
                        else:
                            I.set_cnx_state(I.CNX_TERMINATED, do_lock=1)
                ourid = apiary.util.get_rand_str(prand=1)
                self.cnx = Connection(self.coord, cnxid=ourid)
	    assert self.cnx.connector != self
            if self.cnx.connector:
                self.cnx.connector.fail()
            self.cnx.connector = self
            self.cnx.set_cnx_state(self.cnx.CNX_CONNECTING, do_lock=1)
            self.write_vals = {'localname':self.cnx.coord.app.localname, 'cnxid':ourid,
                               'localprinc':creds[0].name, 'reqdata':req[1]}
            ac.genaddrs(self.cnxsock,
                        flags=krbV.KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR|krbV.KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR)
            self.read_vals['ac'] = ac
            self.read_vals['user'] = remprinc
            assert type(remprinc) == str
            self.state = self.STATE_WRITING
        elif self.state == self.STATE_WRITING:
            self.state = self.STATE_DONE
            self.cnx.initiated = 0
