#  -*- coding: utf-8 -*-
import os
import sys
# import pyasn1
import binascii
import six
from pyasn1_modules import rfc2459, pem
from pyasn1.codec.der import decoder
from datetime import datetime

class Certificate:
    cert_full = ''
    cert = ''
    pyver = ''
    formatCert = ''
    def __init__(self, fileorstr):
        if not os.path.exists(fileorstr):
            strcert = fileorstr.strip('\n')
            if (strcert[0:27] != '-----BEGIN CERTIFICATE-----'):
                return
            idx, substrate = pem.readPemBlocksFromFile(
                six.StringIO(strcert),
                ('-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----')
            )
            self.pyver = sys.version[0]
            try:
                self.cert_full, rest = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())
                self.cert = self.cert_full["tbsCertificate"]
                self.formatCert = 'PEM'
            except:
                self.pyver = ''
                self.formatCert = ''
            return

        self.pyver = sys.version[0]
        filename = fileorstr
        if (self.pyver == '2'):
            if sys.platform != "win32":
                filename = filename.encode("UTF-8")
            else:
                filename = filename.encode("CP1251")
        file1 = open(filename, "rb")
        substrate = file1.read()
        if (self.pyver == '2'):
            b0 = ord(substrate[0])
            b1 = ord(substrate[1])
        else:
            b0 = substrate[0]
            b1 = substrate[1]
        if (b0 == 48 and b1 > 128):
            self.formatCert = 'DER'
        else:
            self.formatCert = 'PEM'
            file1 = open(filename, "r")
            idx, substrate = pem.readPemBlocksFromFile(
                file1,
                ('-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----')
            )
        file1.close()
        try:
            self.cert_full, rest = decoder.decode(substrate, asn1Spec=rfc2459.Certificate())
            self.cert = self.cert_full["tbsCertificate"]
        except:
            self.pyver = ''
            self.formatCert = ''

    def notation_OID(self, oidhex_string):
        hex_list = []
        for char in range(0, len(oidhex_string), 2):
            hex_list.append(oidhex_string[char] + oidhex_string[char + 1])

        del hex_list[0]
        del hex_list[0]

        OID_str = ''

        for element in range(len(hex_list)):
            hex_list[element] = int(hex_list[element], 16)

        x = int(hex_list[0] / 40)
        y = int(hex_list[0] % 40)
        if x > 2:
            y += (x - 2) * 40
            x = 2

        OID_str += str(x) + '.' + str(y)

        val = 0
        for byte in range(1, len(hex_list)):
            val = ((val << 7) | ((hex_list[byte] & 0x7F)))
            if (hex_list[byte] & 0x80) != 0x80:
                OID_str += "." + str(val)
                val = 0

        return (OID_str)

    def subjectSignTool(self):
        if (self.cert == ''):
            return ('')
        for ext in self.cert["extensions"]:
            if (str(ext['extnID']) == "1.2.643.100.111"):
                if sys.platform != "win32":
                    seek = 4
                else:
                    seek = 4

                if (self.pyver == '2'):
                    return ext['extnValue'][seek - 2:]
                seek = seek - 2
                sst = ext['extnValue'][seek:].prettyPrint()
                if (len(sst) > 1 and sst[0] == '0' and sst[1] == 'x'):
                    sst = binascii.unhexlify(sst[2:])
                    sst = sst.decode('utf-8')

                return (sst)
        return ('')
    def identificationKind(self):
        if (self.cert == ''):
            return ('')
        for ext in self.cert["extensions"]:
            if (str(ext['extnID']) == "1.2.643.100.114"):
                return int(ext['extnValue'].prettyPrint()[6:8], 16)
        return ('')

    def issuerSignTool(self):
        if (self.cert == ''):
            return ([])
        for ext in self.cert["extensions"]:
            if (str(ext['extnID']) == "1.2.643.100.112"):
                vv = ext['extnValue']
                of2 = 1
                if (self.pyver == '2'):
                    of1 = ord(vv[of2])
                else:
                    of1 = vv[of2]
                if (of1 > 128):
                    of2 += (of1 - 128)
                of2 += 1
                of2 += 1
                if (self.pyver == '2'):
                    of1 = ord(vv[of2])
                else:
                    of1 = vv[of2]
                if (of1 > 128):
                    of2 += (of1 - 128)
                    of2 += 1
                fsbCA = []
                for j in range(0, 4):
                    if (self.pyver == '2'):
                        ltek = ord(vv[of2])
                        stek = of2 + 1
                    else:
                        ltek = vv[of2 + 0]
                        stek = of2 + 1
                    fsb = vv[stek: stek + ltek]
                    if (self.pyver == '3'):
                        fsb = vv[stek: stek + ltek].prettyPrint()
                        if (len(fsb) > 1 and fsb[0] == '0' and fsb[1] == 'x'):
                            try:
                                val1 = binascii.unhexlify(fsb[2:])
                                fsb = val1.decode('utf-8')
                            except:
                                fsb = vv[stek: stek + ltek].prettyPrint()
                    fsbCA.append(fsb)
                    of2 += (ltek + 2)
                return (fsbCA)
        return ([])

    def classUser(self):
        infoMap = {
            "1.2.643.100.113.1": "KC1",
            "1.2.643.100.113.2": "KC2",
            "1.2.643.100.113.3": "KC3",
            "1.2.643.100.113.4": "KB1",
            "1.2.643.100.113.5": "KB2",
            "1.2.643.100.113.6": "KA1"
        }
        if (self.cert == ''):
            return ('')
        for ext in self.cert["extensions"]:
            if (str(ext['extnID']) == "2.5.29.32"):
                print('2.5.29.32')
                kc = ext['extnValue'].prettyPrint()
                if (self.pyver == '2'):
                    kc_hex = kc[2:]
                else:
                    kc_hex = kc[2:]
                kc_hex = kc_hex[4:]
                i32 = kc_hex.find('300806062a85036471')
                tmp_kc = ''
                while (i32 != -1):
                    kcc_tek = kc_hex[i32 + 4: i32 + 20]
                    oid_kc = self.notation_OID(kcc_tek)
                    tmp_kc = tmp_kc + oid_kc + ';' + infoMap[oid_kc] + ';;'
                    kc_hex = kc_hex[i32 + 20:]
                    i32 = kc_hex.find('300806062a85036471')
                return (tmp_kc)
        return ('')

    def parse_issuer_subject(self, who):
        if (self.cert == ''):
            return ({})
        infoMap = {
            "1.2.840.113549.1.9.2": "unstructuredName",
            "1.2.643.100.1": "OGRN",
            "1.2.643.100.5": "OGRNIP",
            "1.2.643.3.131.1.1": "INN",
            "1.2.643.100.3": "SNILS",
            "2.5.4.3": "CN",
            "2.5.4.4": "SN",
            "2.5.4.5": "serialNumber",
            "2.5.4.42": "GN",
            "1.2.840.113549.1.9.1": "E",
            "2.5.4.7": "L",
            "2.5.4.8": "ST",
            "2.5.4.9": "street",
            "2.5.4.10": "O",
            "2.5.4.11": "OU",
            "2.5.4.12": "title",
            "2.5.4.6": "Country",
            # added
            "1.2.643.100.4": "INNLE"
        }
        issuer_or_subject = {}
        # Владелец сертификата: 0 - неизвестно 1 - физ.лицо 2 - юр.лицо
        vlad = 0
        vlad_o = 0
        for rdn in self.cert[who][0]:
            if not rdn:
                continue
            oid = str(rdn[0][0])
            value = rdn[0][1]
            if (oid == '1.2.643.100.3'):
                vlad = 1
            elif (oid == '1.2.643.100.1'):
                vlad = 2
            elif (oid == '2.5.4.10'):
                vlad_o = 1
            value = value[2:]
            if (self.pyver == '3'):
                val = value.prettyPrint()
                if (len(val) > 1 and val[0] == '0' and val[1] == 'x'):
                    try:
                        val1 = binascii.unhexlify(val[2:])
                        value = val1.decode('utf-8')
                    except:
                        pass
            try:
                if not infoMap[oid] == "Type":
                    issuer_or_subject[infoMap[oid]] = value
                else:
                    try:
                        issuer_or_subject[infoMap[oid]] += ", %s" % value
                    except KeyError:
                        issuer_or_subject[infoMap[oid]] = value
            except KeyError:
                issuer_or_subject[oid] = value
            if (vlad_o == 1):
                vlad = 2
        return issuer_or_subject, vlad

    def issuerCert(self):
        return (self.parse_issuer_subject("issuer"))

    def subjectCert(self):
        return (self.parse_issuer_subject('subject'))

    def signatureCert(self):
        if (self.cert == ''):
            return ({})
        algosign = self.cert_full["signatureAlgorithm"]['algorithm']
        kk = self.cert_full["signatureValue"].prettyPrint()
        if kk[-3:-1] == "'B":
            kk = kk[2:-3]
            kkh = int(kk, 2)
        else:
            kkh = int(kk, 10)
        sign_hex = hex(kkh)
        sign_hex = sign_hex.rstrip('L')
        return (algosign, sign_hex[2:])

    def publicKey(self):
        if (self.cert == ''):
            return ({})
        pubkey = self.cert['subjectPublicKeyInfo']
        tmp_pk = {}
        ff = pubkey['algorithm']
        algo = ff['algorithm']
        tmp_pk['algo'] = algo
        if (str(algo).find("1.2.643") == -1):
            print('НЕ ГОСТ')
            return (tmp_pk)

        param = ff['parameters']
        lh = param.prettyPrint()[2:]
        l1 = int(lh[7:8], 16)
        lh1 = self.notation_OID(lh[4:4 + 4 + l1 * 2])
        l2 = int(lh[4 + 4 + l1 * 2 + 3: 4 + 4 + l1 * 2 + 4], 16)
        lh2 = self.notation_OID(lh[4 + 4 + l1 * 2:4 + 4 + l1 * 2 + 4 + l2 * 2])

        key_bytes = pubkey['subjectPublicKey']
        kk = key_bytes.prettyPrint()
        if kk[-3:-1] == "'B":
            kk = kk[2:-3]
            kkh = int(kk, 2)
        else:
            kkh = int(kk, 10)
        kk_hex = hex(kkh)
        if (kk_hex[3] == '4'):
            kk_hex = kk_hex[5:]
        elif (kk_hex[3] == '8'):
            kk_hex = kk_hex[7:]
        kk_hex = kk_hex.rstrip('L')

        tmp_pk['curve'] = lh1
        tmp_pk['hash'] = lh2
        tmp_pk['valuepk'] = kk_hex
        return (tmp_pk)

    def prettyPrint(self):
        if (self.cert == ''):
            return ('')
        return (self.cert_full.prettyPrint())

    def serialNumber(self):
        return (self.cert.getComponentByName('serialNumber'))

    def validityCert(self):
        valid_cert = self.cert.getComponentByName('validity')
        validity_cert = {}
        not_before = valid_cert.getComponentByName('notBefore')
        not_before = str(not_before.getComponent())

        not_after = valid_cert.getComponentByName('notAfter')
        not_after = str(not_after.getComponent())
        validity_cert['not_before'] = datetime.strptime(
            not_before,
            '%y%m%d%H%M%SZ'
        )
        validity_cert['not_after'] = datetime.strptime(
            not_after,
            '%y%m%d%H%M%SZ'
        )
        return validity_cert

    def KeyUsage(self):
        X509V3_KEY_USAGE_BIT_FIELDS = (
            'digitalSignature',
            'nonRepudiation',
            'keyEncipherment',
            'dataEncipherment',
            'keyAgreement',
            'keyCertSign',
            'CRLSign',
            'encipherOnly',
            'decipherOnly'
        )
        if (self.cert == ''):
            return ([])
        ku = []
        for ext in self.cert["extensions"]:
            if (str(ext['extnID']) != "2.5.29.15"):
                continue
            print('2.5.29.15')
            os16 = ext['extnValue'].prettyPrint()
            os16 = '0404' + os16[2:]
            os = binascii.unhexlify(os16[0:])
            octet_strings = os
            e, f = decoder.decode(
                decoder.decode(octet_strings)[0],
                rfc2459.KeyUsage()
            )
            n = 0
            while n < len(e):
                if e[n]:
                    ku.append(X509V3_KEY_USAGE_BIT_FIELDS[n])
                n += 1
            return (ku)
        return ([])

if __name__ == "__main__":

    c1 = Certificate(sys.argv[1])
    if (c1.pyver == ''):
        print('Context for certificate not create')
        exit(-1)
    print(' ========== formatCert ========== ')
    print(c1.formatCert)
    res = c1.subjectSignTool()
    print(' ========== subjectSignTool ========== ')
    print(res)
    print(' ========== issuerSignTool ========== ')
    res1 = c1.issuerSignTool()
    for ist in range(len(res1)):
        print(str(ist) + '=' + res1[ist])
    print(' ========== classUser ========== ')
    res2 = c1.prettyPrint()
    res3 = c1.classUser()
    print(res3)
    print(' ========== issuerCert ========== ')
    iss, vlad_is = c1.issuerCert()
    print('vlad_is=' + str(vlad_is))
    for key in iss.keys():
        print(key + '=' + iss[key])
    print(' ========== subjectCert ========== ')
    sub, vlad_sub = c1.subjectCert()
    print('vlad_sub=' + str(vlad_sub))
    for key in sub.keys():
        print(key + '=' + sub[key])
    print(' ========== publicKey ========== ')
    key_info = c1.publicKey()
    if (len(key_info) > 0):
        print(key_info['curve'])
        print(key_info['hash'])
        print(key_info['valuepk'])
    print(' ========== serialNumber ========== ')
    print(c1.serialNumber())
    print(' ========== validityCert ========== ')
    valid = c1.validityCert()
    print(valid['not_after'])
    print(valid['not_before'])
    print(' ========== signatureCert ========== ')
    algosign, value = c1.signatureCert()
    print(algosign)
    print(value)
    print(' ========== KeyUsage ========== ')
    ku = c1.KeyUsage()
    for key in ku:
        print(key)
    print(' ========== identificationKind ========== ')
    print(c1.identificationKind())
    print(' ========== END ========== ')
