from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'kerb-as-rep-john'
    description = 'Extract Kerberos AS-REP hashes'

    categories = ['creds', 'windows', 'john']

    pcap_filter = 'kerberos.as_rep_element'

    packet_filter = {'present': ['kerberos.as_rep_element']}

    mandatory_selectors = [
        'kerberos.as_rep_element|kerberos.enc_part_element',
        'kerberos.as_rep_element|kerberos.enc_part_element|kerberos.etype',
        'kerberos.as_rep_element|kerberos.enc_part_element|kerberos.cipher',
    ]

    def parser(self, data):
        etype = data['kerberos.as_rep_element|kerberos.enc_part_element|kerberos.etype'][0]
        cipher = data['kerberos.as_rep_element|kerberos.enc_part_element|kerberos.cipher'][0].replace(':', '')
        realm = data['kerberos|kerberos.as_rep_element|kerberos.crealm'][0]
        username = data['kerberos.as_rep_element|kerberos.cname_element|kerberos.cname_string_tree|kerberos.CNameString'][0]

        if etype == '23':
            self.output(f'$krb5asrep${etype}${username}@{realm}:{cipher[:32]}${cipher[32:]}')
            return 1
        else:
            try:
                salt = data['kerberos.as_rep_element|kerberos.padata_tree|kerberos.PA_DATA_element|kerberos.padata_type_tree|kerberos.padata_value_tree|kerberos.ETYPE_INFO2_ENTRY_element|kerberos.info2_salt'][0]
            except KeyError:
                self.log.error_once('Salt not found in AS_REP packet, cannot build hash.')
                return 0
            self.output(f'$krb5asrep${etype}${salt}${cipher[:-24]}${cipher[-24:]}')
            return 1
