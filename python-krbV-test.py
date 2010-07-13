#!/usr/bin/python

# Simple test script to exercise a few code paths in python-krbV
# Mike Bonnet <mikeb@redhat.com>, 2010-07-12

import sys
import optparse
import socket
import select
import krbV

def handle_tcp(opts, sock):
    conn, addr = sock.accept()
    ctx = krbV.default_context()
    sprinc = krbV.Principal(name=opts.principal, context=ctx)
    keytab = krbV.Keytab(name=opts.keytab, context=ctx)
    ac, cprinc = ctx.recvauth(conn, '1.0',
                              options=krbV.AP_OPTS_MUTUAL_REQUIRED,
                              server=sprinc, keytab=keytab)
    print 'Successfully authenticated via tcp: %s' % cprinc.name
    ac.flags = krbV.KRB5_AUTH_CONTEXT_DO_SEQUENCE|krbV.KRB5_AUTH_CONTEXT_DO_TIME
    ac.genaddrs(conn,
                krbV.KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR|
                krbV.KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR)
    msg_enc = conn.recv(4096)
    msg = ac.rd_priv(msg_enc)
    print '  Received: %s' % msg
    resp_enc = ac.mk_priv(msg)
    conn.send(resp_enc)
    conn.close()

def handle_udp(opts, sock):
    data, addr = sock.recvfrom(4096)
    ctx = krbV.default_context()
    sprinc = krbV.Principal(name=opts.principal, context=ctx)
    keytab = krbV.Keytab(name=opts.keytab, context=ctx)
    ac = krbV.AuthContext(context=ctx)
    ac.flags = krbV.KRB5_AUTH_CONTEXT_DO_SEQUENCE|krbV.KRB5_AUTH_CONTEXT_DO_TIME
    ac, options, sprinc, ccreds = ctx.rd_req(data, server=sprinc, keytab=keytab,
                                             auth_context=ac,
                                             options=krbV.AP_OPTS_MUTUAL_REQUIRED)
    cprinc = ccreds[2]
    print 'Successfully authenticated via udp: %s' % cprinc.name
    rep = ctx.mk_rep(auth_context=ac)
    sock.sendto(rep, addr)
    msg_enc, addr = sock.recvfrom(4096)
    print 'Using addresses: %s' % str((opts.serveraddr[0], opts.serveraddr[1], addr[0], addr[1]))
    ac.addrs = (opts.serveraddr[0], opts.serveraddr[1], addr[0], addr[1])
    msg = ac.rd_priv(msg_enc)
    print '  Received: %s' % msg
    resp_enc = ac.mk_priv(msg)
    sock.sendto(resp_enc, addr)

def handle_connections(opts, socklist):
    while True:
        try:
            rd, wr, ex = select.select(socklist, [], [], 60)
            for sock in rd:
                if sock.type == socket.SOCK_STREAM:
                    handle_tcp(opts, sock)
                elif sock.type == socket.SOCK_DGRAM:
                    handle_udp(opts, sock)
                else:
                    raise ValueError, 'unknown socket type: %s' % sock.type
        except krbV.Krb5Error, e:
            print >> sys.stderr, 'krbV.Krb5Error:', e
        except socket.timeout:
            pass
        except KeyboardInterrupt:
            break

def server(opts):
    print 'Binding to: %s' % str(opts.serveraddr)
    tcpsock = socket.socket(opts.addr_family, socket.SOCK_STREAM)
    tcpsock.settimeout(15)
    tcpsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcpsock.bind(opts.serveraddr)
    tcpsock.listen(5)
    udpsock = socket.socket(opts.addr_family, socket.SOCK_DGRAM)
    udpsock.settimeout(15)
    udpsock.bind(opts.serveraddr)

    try:
        handle_connections(opts, [tcpsock, udpsock])
    finally:
        tcpsock.close()
        udpsock.close()

def tcp_client(opts, conn):
    ctx = krbV.default_context()
    if opts.ccache:
        ccache = krbV.CCache(name='FILE:' + opts.ccache, context=ctx)
    else:
        ccache = ctx.default_ccache()
    cprinc = ccache.principal()
    sprinc = krbV.Principal(name=opts.principal, context=ctx)
    ac = ctx.sendauth(conn, '1.0',
                      options=krbV.AP_OPTS_MUTUAL_REQUIRED,
                      server=sprinc, client=cprinc,
                      ccache=ccache, data='authtest')
    print 'Successfully authenticated via tcp to service: %s' % sprinc.name
    ac.flags = krbV.KRB5_AUTH_CONTEXT_DO_SEQUENCE|krbV.KRB5_AUTH_CONTEXT_DO_TIME
    ac.rcache = ctx.default_rcache()
    ac.genaddrs(conn,
                krbV.KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR|
                krbV.KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR)
    enc_msg = ac.mk_priv(opts.message)
    conn.send(enc_msg)
    enc_resp = conn.recv(4096)
    resp = ac.rd_priv(enc_resp)
    if resp == opts.message:
        print '  Exchanging encrypted messages succeeded'
    conn.close()

def gai_error(opts, addrtype, addr, e):
    af = 'IPv4'
    if opts.addr_family == socket.AF_INET6:
        af = 'IPv6'
    print >> sys.stderr, 'error: Could not get %s address for %s hostname %s' % (af, addrtype, addr)
    print >> sys.stderr, e
    sys.exit(1)

def udp_client(opts, sock, addr):
    ctx = krbV.default_context()
    if opts.ccache:
        ccache = krbV.CCache(name='FILE:' + opts.ccache, context=ctx)
    else:
        ccache = ctx.default_ccache()
    cprinc = ccache.principal()
    sprinc = krbV.Principal(name=opts.principal, context=ctx)
    ac = krbV.AuthContext(context=ctx)
    ac.flags = krbV.KRB5_AUTH_CONTEXT_DO_SEQUENCE|krbV.KRB5_AUTH_CONTEXT_DO_TIME
    ac.rcache = ctx.default_rcache()
    ac, req = ctx.mk_req(server=sprinc, client=cprinc,
                         auth_context=ac, ccache=ccache,
                         options=krbV.AP_OPTS_MUTUAL_REQUIRED)
    sock.sendto(req, addr)
    rep, saddr = sock.recvfrom(4096)
    rep_tup = ctx.rd_rep(rep, auth_context=ac)
    print 'Successfully authenticated via udp to service: %s' % sprinc.name
    try:
        addrinfo = socket.getaddrinfo(socket.gethostname(), sock.getsockname()[1],
                                      opts.addr_family)
        localaddr = addrinfo[0][4]
    except socket.gaierror, e:
        gai_error(opts, 'local', socket.gethostname(), e)
    print 'Using addresses: %s' % str((localaddr[0], localaddr[1], addr[0], addr[1]))
    ac.addrs = (localaddr[0], localaddr[1], addr[0], addr[1])
    msg_enc = ac.mk_priv(opts.message)
    sock.sendto(msg_enc, addr)
    resp_enc, saddr = sock.recvfrom(4096)
    resp = ac.rd_priv(resp_enc)
    if resp == opts.message:
        print '  Exchanging encrypted messages succeeded'

def client(opts):
    print 'Connecting to: %s' % str(opts.serveraddr)

    tcpsock = socket.socket(opts.addr_family, socket.SOCK_STREAM)
    tcpsock.connect(opts.serveraddr)
    tcp_client(opts, tcpsock)

    udpsock = socket.socket(opts.addr_family, socket.SOCK_DGRAM)
    udpsock.settimeout(15)
    udp_client(opts, udpsock, opts.serveraddr)


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('-s', '--server', action='store_true', help='Run in server mode')
    parser.add_option('-p', '--port', type='int', default=11234, help='Port to use for running the test.  The server will bind to this port, and the client will connect to it.')
    parser.add_option('-6', '--ipv6', action='store_true', help='Use IPv6')
    parser.add_option('-a', '--address', default='localhost', help='The address to bind the sockets to in server mode, or the host to connect to in client mode')
    parser.add_option('-P', '--principal', help='The server principal')
    parser.add_option('-k', '--keytab', help='Service keytab')
    parser.add_option('-c', '--ccache', help='Location of the credentials cache')
    parser.add_option('-m', '--message', help='Message to encrypt and send from the client to the server', default='Kerberos is working')

    opts, args = parser.parse_args()

    if not opts.principal:
        parser.error('You must specify the server principal')

    if opts.ipv6:
        opts.addr_family = socket.AF_INET6
    else:
        opts.addr_family = socket.AF_INET

    try:
        addrinfo = socket.getaddrinfo(opts.address, opts.port, opts.addr_family)
        opts.serveraddr = addrinfo[0][4]
    except socket.gaierror, e:
        gai_error(opts, 'server', opts.address, e)

    if opts.server:
        if not opts.keytab:
            parser.error('You must specify a keytab in server mode')
        server(opts)
    else:
        if opts.keytab:
            parser.error('You may only specify a keytab in server mode')
        client(opts)
