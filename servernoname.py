'''
Created on Jun 20, 2011

XMLRPC server to run over HTTPS

@author: mraposa
'''
import socket
import socketserver
import ssl
import pickle
import xmlrpc.client
from xmlrpc.server import SimpleXMLRPCServer, SimpleXMLRPCDispatcher, SimpleXMLRPCRequestHandler
from base64 import b64decode
import os

from ServerInstance import ServerInstance


try:
    import fcntl
except ImportError:
    fcntl = None

import pyrsync

# Configure below
LISTEN_HOST='0.0.0.0' # You should not use '' here, unless you have a real FQDN.
LISTEN_PORT=1356

KEYFILE='key.pem'            # PEM formatted key file
CERTFILE='certificate.pem'  # PEM formatted certificate file
# Configure above

#    Easiest way to create the key file pair was to use OpenSSL -- http://openssl.org/ Windows binaries are available
#    You can create a self-signed certificate easily "openssl req -new -x509 -days 365 -nodes -out cert.pem -keyout privatekey.pem"
#    for more information --  http://docs.python.org/library/ssl.html#ssl-certificates

# molt guarro, pero provisional, aqui i a ma
userPassDict = {"admin":"alsonopass",
                "noadmin":"alsanopass"}

   
class SimpleXMLRPCServerTLS(SimpleXMLRPCServer):
    def __init__(self, addr, requestHandler=SimpleXMLRPCRequestHandler,
                 logRequests=True, allow_none=False, encoding=None, bind_and_activate=True):
        """Overriding __init__ method of the SimpleXMLRPCServer

        The method is an exact copy, except the TCPServer __init__
        call, which is rewritten using TLS
        """
        self.logRequests = logRequests

        SimpleXMLRPCDispatcher.__init__(self, allow_none, encoding)

        """This is the modified part. Original code was:

            socketserver.TCPServer.__init__(self, addr, requestHandler, bind_and_activate)

        which executed:

            def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
                BaseServer.__init__(self, server_address, RequestHandlerClass)
                self.socket = socket.socket(self.address_family,
                                            self.socket_type)
                if bind_and_activate:
                    self.server_bind()
                    self.server_activate()

        """
        class VerifyingRequestHandler(SimpleXMLRPCRequestHandler):
            '''
            Request Handler that verifies username and password passed to
            XML RPC server in HTTP URL sent by client.
            '''
            # this is the method we must override
            def parse_request(self):
                # first, call the original implementation which returns
                # True if all OK so far
                if SimpleXMLRPCRequestHandler.parse_request(self):
                    # next we authenticate
                    if self.authenticate(self.headers):
                        return True
                    else:
                        # if authentication fails, tell the client
                        self.send_error(401, 'Authentication failed')
                return False
           
            def authenticate(self, headers):
                
                #    Confirm that Authorization header is set to Basic
                try:
                    (basic, _, encoded) = headers.get('Authorization').partition(' ')
                    assert basic == 'Basic', 'Only basic authentication supported'
               
                    #    Encoded portion of the header is a string
                    #    Need to convert to bytestring
                    encodedByteString = encoded.encode()
                    #    Decode Base64 byte String to a decoded Byte String
                    decodedBytes = b64decode(encodedByteString)
                    #    Convert from byte string to a regular String
                    decodedString = decodedBytes.decode()
                    #    Get the username and password from the string
                    (username, _, password) = decodedString.partition(':')
                    #    Check that username and password match internal global dictionary
                    if username in userPassDict:
                        if userPassDict[username] == password:
                            return True
                except:
                    pass # Error in headers, ignore it and assume a 401
                return False
       
        #    Override the normal socket methods with an SSL socket
        socketserver.BaseServer.__init__(self, addr, VerifyingRequestHandler)
        self.socket = ssl.wrap_socket(
            socket.socket(self.address_family, self.socket_type),
            server_side=True,
            keyfile=KEYFILE,
            certfile=CERTFILE,
            cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_SSLv23,
            )
        if bind_and_activate:
            self.server_bind()
            self.server_activate()

        """End of modified part"""

        # [Bug #1222790] If possible, set close-on-exec flag; if a
        # method spawns a subprocess, the subprocess shouldn't have
        # the listening socket open.
        if fcntl is not None and hasattr(fcntl, 'FD_CLOEXEC'):
            flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)

# Restrict to a particular path.
class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ('/RPC2',)

def executeServer():
    # Create server
    server = SimpleXMLRPCServerTLS((LISTEN_HOST, LISTEN_PORT), requestHandler=RequestHandler)
    server.register_introspection_functions()
    server.register_instance(ServerInstance())

    # Run the server's main loop
    sa = server.socket.getsockname()
    print ("Serving HTTPS on", sa[0], "port", sa[1])
    server.serve_forever()

if __name__ == '__main__':  
    executeServer()
