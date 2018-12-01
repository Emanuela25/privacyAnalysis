import os
import sys
import signal
from urllib.parse import unquote
import json

from mitmproxy import flowfilter, http, ctx


class collect:
    def __init__(self,file):
        #construct HTTP response code
        self.http_code_ok = flowfilter.parse('~c 200')
        #create a directory for current app's log files "current_directory/logs/file/"
        current_directory = os.getcwd()
        self.folder_name = os.path.join(current_directory, 'logs', file)
        if not os.path.exists(self.folder_name):
                os.makedirs(self.folder_name, 0o777)
        #helper data strucutre
        self.encode = {'identity', 'gzip', 'deflate', 'br'}
        self.host_set = set() #domain set
        #domains known well, no need to record
        self.whiltlist = ['127.0.0.1', 'android.clients.google.com','play.googleapis.com']
        
    # @concurrent 
    def request(self, flow):
        #log all domain names in requests
        host = flow.request.host
        if not host in self.host_set and not host in self.whiltlist:
            self.host_set.add(host)
            
            #process get request url 
            if flow.request.method == "GET":
                url = flow.request.url
                #check if query field has any sensitive keyword inside
                if flow.request.query:
                    for q in flow.request.query:
                        key = q
                        value = flow.request.query[q]
                        print(key, value)
        
            #process post request content
            if flow.request.method == "POST":
                if flow.request.raw_content:
                    req_content = ""
                    if flow.request.headers.get("Content-Encoding", ""):
                        encode_type = flow.request.headers.get("Content-Encoding", "")
                        if not encode_type in self.encode:
                            req_content = ""
                        else:
                            req_content = str(flow.request.content)
                    else:
                        req_content = str(flow.request.content)

                    if req_content:
                        url = flow.request.url
                        req_content_str = str(unquote(req_content[2:-1]))
                        print(url, req_content_str)

addons = [collect(sys.argv[3])]
