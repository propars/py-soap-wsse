from src.soap_wsse.suds_plugin import WssePlugin
from suds.client import Client
from suds.wsse import Security, Timestamp
from suds.bindings import binding
binding.envns=('soap', 'http://www.w3.org/2003/05/soap-envelope')

import logging

logging.basicConfig(level=logging.DEBUG)
# logging.getLogger('suds.client').setLevel(logging.DEBUG)
logging.getLogger('suds.transport').setLevel(logging.DEBUG)
# logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
# logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)

KEY_FILE = "/home/yagiz/Downloads/cert.pem"
EARSIV_TEST_URL = "https://test.efatura.gov.tr/earsiv/services/EArsivWsPort?wsdl"
bin64 = "/home/yagiz/Sourcebox/git/earsiv/output.zip.b64"

wsse = Security()
wsse.tokens.append(Timestamp())
client = Client(url=EARSIV_TEST_URL, wsse=wsse, plugins=[WssePlugin(KEY_FILE), ],)

client.service.sendDocumentFile(Attachment=dict(binaryData=open(bin64, 'rb').read(),
                                                fileName="abfab069-35ce-425f-bd1c-29ff4f24cf0b"))
