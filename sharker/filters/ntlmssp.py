from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'ntlmssp'
    description = 'Extract Net-NTLM hashes for cracking purposes'

    categories = [
        'creds',
        'windows'
    ]

    pcap_filter = 'gss-api || ntlmssp'

    mandatory_selectors = [
        'ntlmssp'
    ]

    def __init__(self, *args, **kwargs):
        self.challenges = {}
        self.challenges_byports = {}
        super().__init__(*args, **kwargs)

    def parser(self, data):
        tcp_conn = data['tcp.stream'][0]
        alt_connection_identifier = (data['tcp.srcport'][0], data['tcp.dstport'][0])
        msg_type = int(data['ntlmssp.messagetype'][0], 16) if 'ntlmssp.messagetype' in data else 0

        if msg_type == 1:
            # NTLM NEGOTIATE: nothing to do
            pass
        elif msg_type == 2:
            # NTLM CHALLENGE
            self.challenges[tcp_conn] = data['ntlmssp.ntlmserverchallenge'][0].replace(':', '')
            self.challenges_byports[alt_connection_identifier] = data['ntlmssp.ntlmserverchallenge'][0].replace(':', '')
        elif msg_type == 3:
            rev_alt = alt_connection_identifier[::-1]
            if tcp_conn not in self.challenges and rev_alt not in self.challenges_byports:
                self.log.error('Found an NTLM message type 3 (AUTH), but no type 2 (CHALLENGE) was received beforehand -> check in pcap if the challenge was not sent in an unsupported by tshark manner from the server, like in a Proxy-Authenticate HTTP header.')
                return 0

            ntresp = data['ntlmssp.auth.ntresponse'][0].replace(':', '')
            lmresp = data['ntlmssp.auth.lmresponse'][0].replace(':', '')
            user = data['ntlmssp.auth.username'][0]
            domain = data['ntlmssp.auth.domain'][0]
            workstation = data['ntlmssp.auth.hostname'][0]

            challenge = self.challenges[tcp_conn] if tcp_conn in self.challenges else self.challenges_byports[rev_alt]

            ntlm_hash = ''
            if len(ntresp) == 24 * 2:
                # NTLMv1 response
                if domain != '':
                    ntlm_hash = f'{user}::{domain}:{lmresp}:{ntresp}:{challenge}'
                else:
                    ntlm_hash = f'{user}::{workstation}:{lmresp}:{ntresp}:{challenge}'
            else:
                # NTLMv2 response
                if domain != '':
                    ntlm_hash = f'{user}::{domain}:{challenge}:{ntresp[:32]}:{ntresp[32:]}'
                else:
                    ntlm_hash = f'{user}::{workstation}:{challenge}:{ntresp[:32]}:{ntresp[32:]}'

            if tcp_conn in self.challenges:
                del self.challenges[tcp_conn]
            if rev_alt in self.challenges_byports:
                del self.challenges_byports[rev_alt]

            self.output(ntlm_hash)
            return 1

        return 0
