######################
# 这是一个通讯测试程序   #
# 用于实现个人设计的流程 #
######################
from urllib.request import urlopen
from urllib.parse import quote
import json


class web_json:
    # initialize here
    def __init__(self, base_url):
        self.base_url = base_url

    # decode message
    def get_url_data(self, params, data):
        web = urlopen(self.base_url + params, data)
        print(web.url)
        print("Status:", web.status)
        rawtext = web.read()
        jsonStr = json.loads(rawtext.decode('utf8'))
        print(json.dumps(jsonStr, sort_keys=False, ensure_ascii=False, indent=2))
        return jsonStr

    # GET
    def url_get(self, params):
        return self.get_url_data(params, None)

    # POST
    def url_post(self, params,data):
        data = bytes(data, 'utf8')
        return self.get_url_data(params,data)

