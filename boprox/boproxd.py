#!/usr/bin/python
'''
Created on Jul 30, 2011

@author: marius
'''

import argparse
import ConfigParser
import server
import auth

import logging

def main():
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
            },
        'Administration': {
            'enabled': '0',
            'pass': 'ChangeMe',
            'tokentimeout': '600'    
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
    parser.add_argument('--debug', dest='loglevel', action='store_const',
        const=logging.DEBUG, default=logging.INFO, 
        help='Be verbose, print debug logs to stdout')
    parser.add_argument('--quiet', dest='loglevel', action='store_const',
        const=logging.WARNING, default=logging.INFO, 
        help='Only print WARNING (and higher) logs')
    args = parser.parse_args()
    logging.basicConfig(level=args.loglevel)
    
    config.read(args.file)
    
    # The configuration... we override it if we have to
    if args.address:
        config.set('Network','address' , args.address )
    if args.port:
        config.set('Network','port', args.port )
    bindtoaddr = (config.get('Network','address'), config.getint('Network', 'port') )
    userauth = auth.UserSQLiteAuth(config.get('Database','dbusers'))
    userauth.setTimeout(config.getint('Administration', 'tokentimeout'))
    # If administration account is enabled, put it in the constant users list
    if config.getboolean('Administration', 'enabled'):
        adminpass = config.get('Administration', 'pass')
        userauth.setConstUsers( ('admin',adminpass) )
    boproxserver = server.AuthXMLRPCServerTLS( bindtoaddr, userauth=userauth,
        keyfile=config.get('Certificates','key') , 
        certfile=config.get('Certificates','cert')
        )
    boproxserver.register_introspection_functions()
    boproxserver.register_instance(server.ServerInstance(boproxserver, config))
    
    sa = boproxserver.socket.getsockname()
    logging.info ("Serving HTTPS on %s port %s", sa[0], str(sa[1]))
    
    boproxserver.serve_forever()

if __name__ == '__main__':
    main()
