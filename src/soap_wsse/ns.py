
dsns = ('ds', 'http://www.w3.org/2000/09/xmldsig#')  # NOQA
ecns = ('ec', 'http://www.w3.org/2001/10/xml-exc-c14n#')  # NOQA
envns = ('soap', 'http://www.w3.org/2003/05/soap-envelope')  # NOQA
wssens = ('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd')  # NOQA
wssns = ('wss', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#')  # NOQA
wsuns = ('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd')  # NOQA
ns1 = ('ns1', 'http://www.w3.org/2003/05/soap-envelope')

NSMAP = dict((envns, dsns, wssens, wsuns, wssns, ns1))