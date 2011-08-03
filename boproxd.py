#!/usr/bin/python
'''
Created on Jul 30, 2011

@author: marius
'''

import argparse
import ConfigParser
import server
import auth

if __name__ == '__main__':
    # First get the defaults
    config = ConfigParser.ConfigParser( {
        # Default values, dictionary
        'Network': {
            'address': '0.0.0.0',
            'port': '1356'             
            },
        'Certificates': {
            'key': '/etc/boprox/key.pem',
            'cert': '/etc/boprox/cert.pem'
            },
        'Directories': {
            'repo': '/var/lib/boprox/repo',
            'hashes': '/var/lib/boprox/hashes',
            'deltas': '/var/lib/boprox/deltas',
            'hards': '/var/lib/boprox/hards'
            },
        'Database': {
            'dbfile': '/var/lib/boprox/file.sqlite',
            'dbusers': '/var/lib/boprox/users.sqlite'            
            }
        } , dict )

    # Argument configuration (command line)
    parser = argparse.ArgumentParser(description='Start the boprox daemon',
        epilog='''The configuration items in the file will be overrided by the 
        command line (if specified).
        ''')
    parser.add_argument('--config', dest='file', default='/etc/boprox/daemon.ini',
        help='File with boprox configuration (default: /etc/boprox/daemon.ini)' )
    parser.add_argument('--address', dest='address' ,
        help='Local host name or ip address')
    parser.add_argument('--port', dest='port' , help='Local port')
    args = parser.parse_args()
    
    config.read(args.file)
    
    # The configuration... we override it if we have to
    if args.address:
        config.set('Network','address' , args.address )
    if args.port:
        config.set('Network','port', args.port )
    bindtoaddr = (config.get('Network','address'), config.getint('Network', 'port') )
    userauth = auth.UserSQLiteAuth(config.get('Database','dbusers'))
    boproxserver = server.AuthXMLRPCServerTLS( bindtoaddr, userauth=userauth,
        keyfile=config.get('Certificates','key') , 
        certfile=config.get('Certificates','cert')
        )
    boproxserver.register_introspection_functions()
    boproxserver.register_instance(server.ServerInstance(boproxserver, config))
    
    sa = boproxserver.socket.getsockname()
    print "Serving HTTPS on", sa[0], "port", sa[1]
    
    boproxserver.serve_forever()