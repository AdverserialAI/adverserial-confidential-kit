import http.client
import json
import threading
import unittest
from unittest.mock import patch
from adverserial_gateway.server import BoundedThreadingHTTPServer, Handler

class Dispatcher:
    def __init__(self):
        self.keys=[]
    def completion(self,key,payload):
        self.keys.append(key)
        return {'choices':[]}

class LocalTokenTests(unittest.TestCase):
    def test_only_the_exact_session_token_is_exchanged_for_the_upstream_key(self):
        dispatcher=Dispatcher()
        class TestHandler(Handler):
            pass
        TestHandler.dispatcher=dispatcher
        server=BoundedThreadingHTTPServer(('127.0.0.1',0),TestHandler)
        server.logger=lambda *_:None
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with patch.dict('os.environ',{'ADVERSERIAL_LOCAL_GATEWAY_TOKEN':'random-session-token','ADVERSERIAL_UPSTREAM_API_KEY':'sk-upstream-secret'}):
                for key in ['random-session-token','wrong-token','sk-direct-key']:
                    connection=http.client.HTTPConnection(*server.server_address,timeout=2)
                    connection.request('POST','/v1/chat/completions',json.dumps({'model':'lordx64/cyberglm','messages':[]}),{'Content-Type':'application/json','Authorization':'Bearer '+key})
                    response=connection.getresponse();self.assertEqual(response.status,200);self.assertNotIn(b'sk-upstream-secret',response.read());connection.close()
            self.assertEqual(dispatcher.keys,['sk-upstream-secret','wrong-token','sk-direct-key'])
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)
