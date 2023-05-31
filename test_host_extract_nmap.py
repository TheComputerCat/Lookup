import host_extract_nmap
import unittest

from common import (
    createFixture,
    writeStringToFile,
    setUpWithATextFile,
    tearDownWithATextFile,
    getStringFromFile
)

withATextFile = createFixture(setUpWithATextFile, tearDownWithATextFile)

class TestHelpers(unittest.TestCase):
    XMLContentExample = r"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
<host starttime="1684970000" endtime="1684970001">
<hostnames>
<hostname name="pepe.com" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="21"><state state="filtered"/><service name="ftp" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="filtered"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="8008"><state state="open" /><service name="http" servicefp="SF-Port8008-TCP:V=7.80%I=2%D=5/25%Time=646EB137%P=x86_64-pc-linux-gnu%r(GetRequest,D3,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015/\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;)%r(FourOhFourRequest,F6,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015/nice%20ports%2C/Tri%6Eity\.txt%2ebak\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;)%r(GenericLines,D2,&quot;HTTP/1\.1\x20302\x20Found\r\nLocation:\x20https://:8015\r\nConnection:\x20close\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-XSS-Protection:\x201;\x20mode=block\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Security-Policy:\x20frame-ancestors\x20&apos;self&apos;\r\n\r\n&quot;);" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>"""

    @withATextFile(pathToTextFile='./data/host1', content=XMLContentExample)
    def test_getHostElementFromXML(self):
        result_host = host_extract_nmap.getHostElementFromXML('./data/host1')
        self.assertEqual(result_host.tag,'host')

    
    # @withATextFile(pathToTextFile='./data/host1', content='domain\ngoogle.com\nfacebook.com')
    # def test_getTimeStamp(self):



if __name__ == "__main__":
    unittest.main()
