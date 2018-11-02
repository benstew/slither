"""
Module detecting timestamp dependence
"""

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class UnusedStateVars(AbstractDetector):
    """
    Timestamp dependence detector
    """

    ARGUMENT = 'timestamp-dependence'
    HELP = 'Timestamp Dependence'
    IMPACT = DetectorClassification.INFORMATIONAL
    CONFIDENCE = DetectorClassification.HIGH

    def detect_timestamp(self, contract):
        if contract.is_signature_only():
            return None

        # Get all the variables read in all the functions and modifiers
        variables_used = [x.state_variables_read + x.state_variables_written for x in
                          (contract.all_functions_called + contract.modifiers)]
        # Flat list
        variables_used = [item for sublist in variables_used for item in sublist]
        # Return the variables unused that are not public
        return [x for x in contract.variables if
                x not in variables_used and x.visibility != 'public']

    def detect(self):
        """ Detect timestamp dependence
        """
        results = []
        for c in self.slither.contracts_derived:
            timestampDeps = self.detect_timestamp(c)

            if timestampDeps:
                timestampDepsName = [v.name for v in timestampDeps]
                info = "Unused state variables in %s, Contract: %s, Vars %s" % (self.filename,
                                                                                c.name,
                                                                                str(timestampDepsName))
                self.log(info)

                sourceMapping = [v.source_mapping for v in timestampDeps]

                results.append({'vuln': 'timestampeDependence',
                                'sourceMapping': sourceMapping,
                                'filename': self.filename,
                                'contract': c.name,
                                'timestampeDependence': timestampDepsName})
        return results
