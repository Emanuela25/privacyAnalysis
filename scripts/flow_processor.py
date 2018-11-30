import os
import sys
import signal

from mitmproxy import flowfilter, http, ctx

class MyAddon:
    def __init__(self,file):
        #construct HTTP response code
        self.http_code_ok = flowfilter.parse('~c 200')

        current_directory = os.getcwd()
        self.folder_name = os.path.join(current_directory, 'logs', file)
        if not os.path.exists(self.folder_name):
                os.makedirs(self.folder_name, 0o777)
            
        self.host_file_name = self.folder_name + '/' + file + '_domains.txt'
        self.whiltlist = ['127.0.0.1']
        self.host_set = set()
        
    # @concurrent 
    def request(self, flow):
        #log all domain names in requests
        host = flow.request.host
        if not host in self.host_set and not host in self.whiltlist:
            self.host_set.add(host)
            with open(self.host_file_name,'a+') as f:
                f.write(host + '\n')
        
        #process get request url 
        if flow.request.method == "GET":
            url = flow.request.url
            if flow.request.query:
                print(url)
                for q in flow.request.query:
                    print(q)
            

        #process post request content
        if flow.request.content:
            req_content = str(flow.request.content)
            #ctx.log('request content: %s' % req_content)

addons = [MyAddon(sys.argv[3])]
