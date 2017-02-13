"""
    soap_wsse.signing
    ~~~~~~~~~~~~~~~~~

    Library to sign SOAP requests with WSSE tokens.

"""
import logging
import base64
import os
import socket
from uuid import uuid4

import xmlsec
# from dm.xmlsec.binding.tmpl import Signature
from lxml import etree
from OpenSSL import crypto

from src.soap_wsse import ns


logger = logging.getLogger(__name__)


BODY_XPATH = etree.XPath(
    '/soap:Envelope/ns1:Body', namespaces=ns.NSMAP)
HEADER_XPATH = etree.XPath(
    '/soap:Envelope/soap:Header', namespaces=ns.NSMAP)
SECURITY_XPATH = etree.XPath('wsse:Security', namespaces=ns.NSMAP)
SIGNATURE_XPATH = etree.XPath('ds:Signature', namespaces=ns.NSMAP)
KEYINFO_XPATH = etree.XPath('ds:KeyInfo', namespaces=ns.NSMAP)
TIMESTAMP_XPATH = etree.XPath('wsu:Timestamp', namespaces=ns.NSMAP)

C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
XMLDSIG_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256'


def ns_id(tagname, suds_ns):
    return '{{{0}}}{1}'.format(suds_ns[1], tagname)

WSU_ID = ns_id('Id', ns.wsuns)
BINARY_TOKEN_TYPE = (
    'http://docs.oasis-open.org/wss/2004/01/' +
    'oasis-200401-wss-x509-token-profile-1.0#X509v3')


def log_errors(filename, line, func, error_object, error_subject, reason, msg):
    info = []
    if error_object != 'unknown':
        info.append('obj=' + error_object)
    if error_subject != 'unknown':
        info.append('subject=' + error_subject)
    if msg.strip():
        info.append('msg=' + msg)
    if info:
        logger.debug('%s:%d(%s)' % (filename, line, func), ' '.join(info))


class CertificationError(Exception):
    pass


# Initialize the xmlsec library
# xmlsec.initialize()
# xmlsec.set_error_callback(log_errors)


class SignQueue(object):
    WSU_ID = ns_id('Id', ns.wsuns)
    DS_DIGEST_VALUE = ns_id('DigestValue', ns.dsns)
    DS_REFERENCE = ns_id('Reference', ns.dsns)
    DS_TRANSFORMS = ns_id('Transforms', ns.dsns)

    def __init__(self):
        self.queue = []

    def push_and_mark(self, element):
        unique_id = get_unique_id()
        element.set(self.WSU_ID, unique_id)
        self.queue.append(unique_id)

    def insert_references(self, signature):
        signed_info = signature.find('ds:SignedInfo', namespaces=ns.NSMAP)
        nsmap = {ns.ecns[0]: ns.ecns[1]}

        for element_id in self.queue:
            reference = etree.SubElement(
                signed_info, self.DS_REFERENCE,
                {'URI': '#{0}'.format(element_id)})
            transforms = etree.SubElement(reference, self.DS_TRANSFORMS)
            node = set_algorithm(transforms, 'Transform', C14N)

            elm = _create_element(node, 'ec:InclusiveNamespaces', nsmap)
            elm.set('PrefixList', 'urn')

            set_algorithm(reference, 'DigestMethod', XMLDSIG_SHA256)
            etree.SubElement(reference, self.DS_DIGEST_VALUE)


def sign_wss(xml_envelope):
    xml_signed = b""

    SIGNER_IP = "localhost"
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


def verify_envelope(reply, key_file):
    """Verify that the given soap request is signed with the certificate"""
    doc = etree.fromstring(reply)
    (header,) = HEADER_XPATH(doc)
    security = SECURITY_XPATH(header)
    signature = SIGNATURE_XPATH(security)
    
    if signature is None:
        raise CertificationError("No signature node found")
    
    dsig_ctx = xmlsec.SignatureContext()

    xmlsec.tree.add_ids(doc, ['Id'])
    sign_key = xmlsec.Key.from_file(key_file, xmlsec.KeyFormat.PEM)
    sign_key.name = os.path.basename(key_file)

    dsig_ctx.key = sign_key
    try:
        dsig_ctx.verify(signature)
    except xmlsec.VerificationError:
        return False
    return True


def get_unique_id():
    return 'id-{0}'.format(uuid4())


def set_algorithm(parent, name, value):
    return etree.SubElement(parent, ns_id(name, ns.dsns), {'Algorithm': value})


def get_body(envelope):
    (body,) = BODY_XPATH(envelope)
    return body


def create_key_info_node(security_token):
    """Create the KeyInfo node for WSSE.

    Note that this currently only supports BinarySecurityTokens

    Example of the generated XML:

        <ds:KeyInfo Id="KI-24C56C5B3448F4BE9D141094243396829">
            <wsse:SecurityTokenReference
                wsse11:TokenType="{{ BINARY_TOKEN_TYPE }}">
                <wsse:Reference
                    URI="#X509-24C56C5B3448F4BE9D141094243396828"
                    ValueType="{{ BINARY_TOKEN_TYPE }}"/>
           </wsse:SecurityTokenReference>
        </ds:KeyInfo>

    """

    sec_token_ref = etree.Element(ns_id('SecurityTokenReference', ns.wssens))
    sec_token_ref.set(ns_id('TokenType', ns.wssens), security_token.get('ValueType'))
    reference = etree.SubElement(sec_token_ref, ns_id('Reference', ns.wssens))
    reference.set('ValueType', security_token.get('ValueType'))
    reference.set('URI', '#%s' % security_token.get(WSU_ID))
    return sec_token_ref


def create_binary_security_token(key_file):
    """Create the BinarySecurityToken node containing the x509 certificate.

    """
    node = etree.Element(
        ns_id('BinarySecurityToken', ns.wssens),
        nsmap={ns.wssens[0]: ns.wssens[1]})
    node.set(ns_id('Id', ns.wsuns), get_unique_id())
    node.set('EncodingType', ns.wssns[1] + 'Base64Binary')
    node.set('ValueType', BINARY_TOKEN_TYPE)

    with open(key_file, 'rb') as fh:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, fh.read())
        node.text = base64.b64encode(
            crypto.dump_certificate(crypto.FILETYPE_ASN1, cert))
    return node


def ensure_security_header(envelope, queue):
    """Insert a security XML node if it doesn't exist otherwise update it.

    """
    (header,) = HEADER_XPATH(envelope)
    security = SECURITY_XPATH(header)
    if security:
        for timestamp in TIMESTAMP_XPATH(security[0]):
            queue.push_and_mark(timestamp)
        return security[0]
    else:
        nsmap = {
            'wsu': ns.wsuns[1],
            'wsse': ns.wssens[1],
        }
        return _create_element(header, 'wsse:Security', nsmap)


def _create_element(parent, name, nsmap):
    prefix, name = name.split(':', 1)
    tag_name = '{%s}%s' % (nsmap[prefix], name)

    if parent is not None:
        return etree.SubElement(parent, tag_name, nsmap=nsmap)
    else:
        return etree.Element(tag_name, nsmap=nsmap)
