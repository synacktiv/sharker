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
        super().__init__(*args, **kwargs)

    def parser(self, data):
        tcp_conn = data['tcp.stream'][0]
        msg_type = int(data['ntlmssp.messagetype'][0], 16) if 'ntlmssp.messagetype' in data else 0

        if msg_type == 1:
            # NTLM NEGOTIATE: nothing to do
            pass
        elif msg_type == 2:
            # NTLM CHALLENGE
            self.challenges[tcp_conn] = data['ntlmssp.ntlmserverchallenge'][0].replace(':', '')
        elif msg_type == 3:
            if tcp_conn not in self.challenges:
                self.log.error('Found an NTLM message type 3 (AUTH), but no type 2 (CHALLENGE) was received beforehand -> check in pcap if the challenge was not sent in an unsupported by tshark manner from the server, like in a Proxy-Authenticate HTTP header.')
                return 0

            ntresp = data['ntlmssp.auth.ntresponse'][0].replace(':', '')
            lmresp = data['ntlmssp.auth.lmresponse'][0].replace(':', '')
            user = data['ntlmssp.auth.username'][0]
            domain = data['ntlmssp.auth.domain'][0]
            workstation = data['ntlmssp.auth.hostname'][0]

            ntlm_hash = ''
            if len(ntresp) == 24 * 2:
                # NTLMv1 response
                if domain != '':
                    ntlm_hash = f'{user}::{domain}:{lmresp}:{ntresp}:{self.challenges[tcp_conn]}'
                else:
                    ntlm_hash = f'{user}::{workstation}:{lmresp}:{ntresp}:{self.challenges[tcp_conn]}'
            else:
                # NTLMv2 response
                if domain != '':
                    ntlm_hash = f'{user}::{domain}:{self.challenges[tcp_conn]}:{ntresp[:32]}:{ntresp[32:]}'
                else:
                    ntlm_hash = f'{user}::{workstation}:{self.challenges[tcp_conn]}:{ntresp[:32]}:{ntresp[32:]}'

            del self.challenges[tcp_conn]
            self.output(ntlm_hash)
            return 1

        return 0
