# Define and implement 5G Core sequence procedures

# Create class for Registration Procedure
class RegistrationProcedure(Sequence):
    """ General Registration TS 23.502 Section 4.2.2.2.2 
        
        Sequence Diagram:
        UE ----> gNB ----> AMF ----> SMF
        UE <---- gNB <---- AMF <---- SMF
    """
    def __init__(self, ue, gnb, amf, smf):
        super().__init__()
        self.ue = ue
        self.gnb = gnb
        self.amf = amf
        self.smf = smf
        self._sequence = [
            self._initial_ue_message,
            self._downlink_nas_transport, # Authentication Request, AMF --> gNB --> UE
            self._uplink_nas_transport, # Authentication Response, UE --> gNB --> AMF
            self._downlink_nas_transport, # Security Mode Command, AMF --> gNB --> UE
            self._uplink_nas_transport, # Security Mode Complete, UE --> gNB --> AMF
            self._intial_context_setup_request, # Initial Context Setup Request, AMF --> gNB
            self._intial_context_setup_response, # Initial Context Setup Response, gNB --> AMF
        ]
    
    def recv(self, data: bytes) -> None:
        """ Receive data from the socket. """
        PDU = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        PDU.from_aper(data)
        print(PDU.to_asn1())
        # Select the next step in the sequence
        self._selector(PDU)

    def send(self, data: bytes) -> int:
        """ Send data to the socket. """
        pass

    def _selector(self, pdu) -> int:
        """ Select the next step in the sequence. """
        # Get the PDU type
        pdu_type = pdu[1]['value'][0]

    def _initial_ue_message(self):
        """ Initial UE Message TS 23.502 Section
        """

    def _downlink_nas_transport(self):
        """ Downlink NAS Transport TS 23.502 Section
        """

    def _uplink_nas_transport(self):
        """ Uplink NAS Transport TS 23.502 Section
        """

    def _intial_context_setup_request(self):
        """ Initial Context Setup Request TS 23.502 Section
        """

    def _intial_context_setup_response(self):
        """ Initial Context Setup Response TS 23.502 Section
        """

    def _run(self):
        """ Run the sequence. """
        for step in self._sequence:
            step()