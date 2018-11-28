import os
import sys

from mitmproxy import flowfilter, http, ctx

class MyAddon:
    def __init__(self, file):
        #construct HTTP response code
        self.http_code_ok = flowfilter.parse('~c 200')
        self.file_name = file + '.txt'

    # @concurrent 
    def request(self, flow):
        #log all host name in requests
        host = flow.request.host
        with open(self.file_name,'a+') as f:
                    f.write(host + '\n')

    def response(self, flow):
        if flowfilter.match(self.http_code_ok, flow):
            """when code is 200 ok"""
            if flow.response.content:
                res_content = str(flow.response.content)
                """Todo: regex to detect private data leak"""
                #ctx.log('response content %s' % res_content)
                


addons = [ MyAddon(sys.argv[3]) ]