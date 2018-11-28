import os
import sys

from mitmproxy import flowfilter, http, ctx

class MyAddon:
    def __init__(self, file):
        #construct HTTP response code
        self.http_code_ok = flowfilter.parse('~c 200')
        self.file_name = file + '.txt'
        self.log = dict()
        self.log['domains'] = set()

    # @concurrent 
    def request(self, flow):
        #log all host name in requests
        host = flow.request.host
        log['domains'].add(host)
        with open(self.file_name,'a+') as f:
                    f.write(host + '\n')
        if flow.request.content:
            req_content = str(flow.request.content)
            ctx.log('request content: %s' % req_content)

    def response(self, flow):
        if flowfilter.match(self.http_code_ok, flow):
            """when code is 200 ok"""
            if flow.response.content:
                res_content = str(flow.response.content)
                #ctx.log('response content %s' % res_content)
                


addons = [ MyAddon(sys.argv[3]) ]