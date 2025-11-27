from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'kerb-as-req-hashcat'
    description = 'Extract Kerberos AS-REQ hashes'

    categories = ['creds', 'windows', 'hashcat']

    pcap_filter = 'kerberos'

    mandatory_selectors = [
        'kerberos'  # We want to match both AS_REQs and Kerberos PA required errors
    ]

    # Salts
    salts = {}
    # Client names and Service names per UDP/TCP connections
    tmp_name_tcp = {}
    tmp_name_udp = {}

    def gen_hash(self, etype, client_name, service_name, packet_hash, salt, domain):

        if client_name.endswith('$'):
            self.log.info(f'Got an AS_REQ for a machine account ({client_name}), no hash generated.')
            return 0

        if etype == "23":
            first_hash_part = packet_hash[32:]
            second_hash_part = packet_hash[:32]
            self.output(f'$krb5pa${etype}${client_name}${domain}$doesnotmatter${first_hash_part}{second_hash_part}')
        else:
            if salt is None:
                self.log.warning_once('Got a Kerberos pre-authentication (other than RC4) without prior salt given by the KDC. Salt will be guessed by hashcat.')
                if '.' not in domain:
                    self.log.warning_once('Retrieved domain does not seem to be the FQDN, the salt required for Kerberos AES computation likely needs the FQDN, you will have to patch the hash manually with the domain FQDN.')
                service_name = domain
            elif f'{domain}{client_name}' != salt:
                # Special case for hashcat that does not support specifying the salt directly in the hash
                self.log.error(f'The real salt does not match the concatenation "{{domain}}{{username}}". Expected: {domain}{client_name}, got real salt {salt}. Hashcat will use the wrong salt, please adapt username and domains in hash to match this salt (case sensitive): {salt} .')
                if '.' not in domain:
                    self.log.warning_once('Retrieved domain does not seem to be the FQDN, the salt required for Kerberos AES computation likely needs the FQDN, you will have to patch the hash manually with the domain FQDN.')
                service_name = domain.upper()
            else:
                service_name = salt[:-len(client_name)]

            self.output(f'$krb5pa${etype}${client_name}${service_name}${packet_hash}')

        return 1

    def parser(self, data):
        if 'kerberos.as_req_element' in data:
            # We got an AS_REQ

            client_name, service_name = data['kerberos|kerberos.as_req_element|kerberos.req_body_element|kerberos.cname_element|kerberos.cname_string_tree|kerberos.CNameString'][0],\
                '/'.join(data['kerberos|kerberos.as_req_element|kerberos.req_body_element|kerberos.sname_element|kerberos.sname_string_tree|kerberos.SNameString'][0])

            if 'kerberos|kerberos.as_req_element|kerberos.padata_tree|kerberos.PA_DATA_element' in data:
                padata_elts = data['kerberos|kerberos.as_req_element|kerberos.padata_tree|kerberos.PA_DATA_element']
                if isinstance(padata_elts[0], list):
                    padata_elts = padata_elts[0]

                for padata_elt in padata_elts:
                    if padata_elt['kerberos.padata_type'] == '2':
                        # Encrypted timestamp

                        # realm = data['kerberos.realm'][0]
                        realm = data['kerberos|kerberos.as_req_element|kerberos.req_body_element|kerberos.sname_element|kerberos.sname_string_tree|kerberos.SNameString'][0][1]
                        etype = data["kerberos.etype"][0]
                        packet_hash = data["kerberos.cipher"][0].replace(":", "")
                        try:
                            salt = self.salts[(client_name, service_name)]
                        except KeyError:
                            salt = None

                        return self.gen_hash(etype, client_name, service_name, packet_hash, salt, realm)

            # No encrypted timestamp
            # Save the client name and service name for current Kerberos exchange
            if 'tcp.stream' in data:
                self.tmp_name_tcp[data['tcp.stream'][0]] = (client_name, service_name)
                self.log.debug(f'Client name/service name for tcp stream: {client_name}, {service_name}.')
            elif 'udp.stream' in data:
                self.tmp_name_udp[data['udp.stream'][0]] = (client_name, service_name)
                self.log.debug(f'Client name/service name for udp stream: {client_name}, {service_name}.')

            # Nothing else to do for AS_REQ here

        elif 'kerberos.krb_error_element' in data:
            # Kerberos error
            if data['kerberos|kerberos.krb_error_element|kerberos.error_code'][0] != '25':
                # Not a KRB5KDC_ERR_PREAUTH_REQUIRED error
                return 0

            # Finding salt
            try:
                salt = data['kerberos|kerberos.krb_error_element|kerberos.e_data_tree|kerberos.PA_DATA_element|kerberos.padata_type_tree|kerberos.padata_value_tree|kerberos.ETYPE_INFO2_ENTRY_element|kerberos.info2_salt'][0]
            except KeyError:
                self.log.warning_once('Got a KRB5KDC_ERR_PREAUTH_REQUIRED without AES salt, are machines only using RC4 in this network?')
                return 0

            # Matching salt to client_name and service_name
            try:
                if 'tcp.stream' in data:
                    client_name, service_name = self.tmp_name_tcp[data['tcp.stream'][0]]
                elif 'udp.stream' in data:
                    client_name, service_name = self.tmp_name_udp[data['udp.stream'][0]]
            except KeyError:
                self.log.warning_once('Got a Kerberos salt that does not match any identified AS_REQ.')
                return 0

            # Save binding (client_name, server_name) -> salt
            self.salts[(client_name, service_name)] = salt
            self.log.debug(f'Found salt {repr(salt)} for ({client_name}, {service_name}).')

        return 0
