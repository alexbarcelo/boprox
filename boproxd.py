#!/usr/bin/python3
'''
Created on Jul 30, 2011

@author: marius
'''

import argparse
import configparser
import server
import auth

if __name__ == '__main__':
    # First get the defaults
    config = configparser.ConfigParser()
    config.read_dict( {
        'Network': {
            'address': '0.0.0.0',
            'port': '1356'             
            },
        'Certificates': {
            'key': '/etc/boprox/key.pem',
            'cert': '/etc/boprox/certificate.pem'
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
        } )

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
    
    # No try:except: needed --an error here will be fatal
    f = open (args.file, 'r' )
    config.read_file(f)
    
    # The configuration... we override it if we have to
    if args.address:
        config['Network']['address'] = args.address
    if args.port:
        config['Network']['port'] = args.port
    bindtoaddr = (config['Network']['address'], int(config['Network']['port']))
    userauth = auth.UserSQLiteAuth(config['Database']['dbusers'])
    boproxserver = server.AuthXMLRPCServerTLS( bindtoaddr, userauth=userauth,
        keyfile=config['Certificates']['key'] , 
        certfile=config['Certificates']['cert']
        )
    boproxserver.register_introspection_functions()
    boproxserver.register_instance(server.ServerInstance(server, config))
    
    boproxserver.serve_forever()