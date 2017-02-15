import sys, os, socket

#sys.path.append(os.path.abspath("src"))


# pip install -e . komutu gerektirir
from suds.plugin import MessagePlugin
from suds.client import Client
from suds.wsse import Security, Timestamp
from suds.bindings import binding
binding.envns=('soap', 'http://www.w3.org/2003/05/soap-envelope')
from soap_wsse.signing import SignQueue, ensure_security_header, create_binary_security_token, get_body
from soap_wsse.signing import HEADER_XPATH, SECURITY_XPATH, SIGNATURE_XPATH, KEYINFO_XPATH, create_key_info_node

import logging

#logging.basicConfig(level=logging.DEBUG)
# logging.getLogger('suds.client').setLevel(logging.DEBUG)
#logging.getLogger('suds.transport').setLevel(logging.DEBUG)
# logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
# logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)

#KEY_FILE = "/home/ugur/workspace/edevlet-crypto/cert/depo/cert.pem"
KEY_FILE = "/home/ugur/keyy.pem"
EARSIV_TEST_URL = "https://portal.efatura.gov.tr/earsiv/services/EArsivWsPort?wsdl"
#bin64 = "/home/yagiz/Sourcebox/git/earsiv/output.zip.b64"

wsse = Security()
wsse.tokens.append(Timestamp())



def sign_wss(xml_envelope):
    xml_signed = b""

    SIGNER_IP = "localhost"#"172.17.0.96"
    SIGNER_PORT = 33333

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect((SIGNER_IP, SIGNER_PORT))
    sock.send(b"signWSS\n" + xml_envelope)
    sock.shutdown(socket.SHUT_WR)

    while True:
        readbuf = sock.recv(4096)
        if not readbuf:  # Daha fazla okuyacak birsey yok
            break
        else:
            xml_signed += readbuf

    return xml_signed


def sign_envelope(envelope, key_file):
    """Sign the given soap request with the given key"""
    doc = etree.fromstring(envelope)
    body = get_body(doc)

    queue = SignQueue()
    queue.push_and_mark(body)

    security_node = ensure_security_header(doc, queue)
    security_token_node = create_binary_security_token(key_file)
    security_node.append(security_token_node)

    signed_envelope = sign_wss(etree.tostring(doc))
    signed_etree = etree.fromstring(signed_envelope)


    (header,) = HEADER_XPATH(signed_etree)
    security = SECURITY_XPATH(header)
    signature = SIGNATURE_XPATH(security[0])
    keyinfo = KEYINFO_XPATH(signature[0])
    key_info = create_key_info_node(security_token_node)

    # java imzacinin koydugu ve gib'in begenmedigi SecurityTokenReference kaldirilir
    java_keyinfo = keyinfo[0].find("{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}SecurityTokenReference")
    keyinfo[0].remove(java_keyinfo)

    keyinfo[0].append(key_info)

    return etree.tostring(signed_etree)




from lxml import etree
import re
import base64



def gib_parser(reply):
    #reply = reply.replace(b'\r\n', b'\n')
    parts = reply.strip().split(b'--uuid:')
    parts_dict = {}
    root_part = None

    for part in parts:
        if not part.strip():
            continue
        if len(part) == 38 and part[-2:] == b'--':      # son kapanis isareti
            continue

        sub_parts = part.split(b'\r\n\r\n')
        head = sub_parts[0]
        body = b'\r\n\r\n'.join(sub_parts[1:])
        cid = head.split(b'Content-ID:')[1].strip()
        parts_dict[cid] = body
        if cid == b"<root.message@cxf.apache.org>":
            root_part = body
    assert root_part
    if b'<xop:Include' in root_part:
        inc = re.search(b"<xop\:Include .* ?/>", root_part).group(0)
        inc_cid = '<{}>'.format(re.search(b'href="(.*)"', inc).group(1).replace(b'cid:', b'').decode("utf-8")).encode('utf-8')
         #root_part = root_part.replace(inc, parts_dict[inc_cid])
        #root_part = root_part.replace(inc, b'<[CDATA['+parts_dict[inc_cid]+b']]>')
        root_part = root_part.replace(inc, base64.encodebytes(parts_dict[inc_cid]))
    return root_part



class WssePlugin(MessagePlugin):
    """Suds plugin to sign soap requests with a certificate"""

    def __init__(self, filename):
        self.cert_filename = filename

    def sending(self, context):
        context.envelope = sign_envelope(context.envelope, self.cert_filename)

        from xml.dom.minidom import parseString
        parsed = parseString(context.envelope.replace(b'\n', b'').replace(b'\t', b''))
        pretty = parsed.toprettyxml()
        with open("sending.xml", "w") as w:
            w.write(pretty)

    def received(self, context):
        if context.reply:
            with open("cevap", "wb") as c:
                c.write(context.reply)
            """
            answerDecoded = context.reply.decode("iso-8859-9")
            xmlMessage = re.search(r'(<soap\:Envelope.*)\r', answerDecoded)
            replyFinal = xmlMessage.group(1)+'\n'
            replyFinalDecoded = replyFinal.encode()
            """
            context.reply = gib_parser(context.reply)
            with open("cevap2", "wb") as c:
                c.write(context.reply)
            #valid = verify_envelope(context.reply, self.cert_filename)
            #if not valid:
            #    raise CertificationError("Failed to verify response")


client = Client(url=EARSIV_TEST_URL, wsse=wsse, plugins=[WssePlugin(KEY_FILE), ],)

response = client.service.getUserList("XML")
import base64, zipfile
from io import BytesIO
from lxml import etree
bz = base64.decodestring(response.binaryData.encode("utf-8"))
zi = zipfile.ZipFile(BytesIO(bz))
userlist_xml = zi.read(zi.namelist()[0])
root = etree.fromstring(userlist_xml)
for user in root.findall("User"):
    print('Identifier', user.find('Identifier').text)
    print(user.find('Title').text)
    print(user.find('Type').text)
    print(user.find('FirstCreationTime').text)
    print(user.find('ActivationTime').text)
    print(user.find('DeactivationTime').text)



#sendDocumentFile(Attachment=dict(binaryData=open(bin64, 'rb').read(),
#                                                fileName="abfab069-35ce-425f-bd1c-29ff4f24cf0b"))
