from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'kerb-tgs-rep-john'

    description = 'Extract Kerberos TGS-REP hashes'

    categories = ['creds', 'windows', 'john']

    pcap_filter = 'kerberos.tgs_rep_element'

    packet_filter = {'present': ['kerberos.tgs_rep_element']}

    mandatory_selectors = ['kerberos.tgs_rep_element|kerberos.ticket_element']

    def parser(self, data):
        ticket = data['kerberos.tgs_rep_element|kerberos.ticket_element'][0]
        etype = ticket['kerberos.enc_part_element']['kerberos.etype']

        # This is required for hashcat to compute the salt for AES* encryptions
        realm = ticket['kerberos.realm']
        username = '!!!!!WARNING: fix with sAMAccountName of service user!!!!!'

        # Just indicative
        spn_entries = ticket['kerberos.sname_element']['kerberos.sname_string_tree']['kerberos.SNameString']
        spn = ('/'.join(spn_entries) if type(spn_entries) == list else spn_entries)

        cipher = ticket['kerberos.enc_part_element']['kerberos.cipher'].replace(':', '')

        if etype == '23':
            self.output(f'$krb5tgs${etype}$*doesnotmatter${realm}${spn}*${cipher[:32]}${cipher[32:]}')
            return 1
        else:
            self.log.warning_once('Found an AES encrypted ticket in a Kerberos TGS-REP, you will have to manually complete the hash with the service\'s sAMAccountName (that we cannot accurately retrieve) to bruteforce it.')

            if '.' not in realm:
                self.log.warning_once('Retrieved domain does not seem to be the FQDN, the salt required for Kerberos AES computation likely needs the FQDN, you will have to patch the salt manually with the domain FQDN.')

            self.output(f'$krb5tgs${etype}${username}${realm}$*{spn}*${cipher[-24:]}${cipher[:-24]}')
            return 1
