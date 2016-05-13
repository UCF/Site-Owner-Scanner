**High Priority**
> 1. Improve domain owner comparison speed
> 2. Export scan result data to xls spreadsheet

**Medium Priority**
> 1. Standardize DNS IP mappings in spreadsheet
> 2. Eliminate data assumptions (see below)
> 3. Load CSV files as singular task (currently two)
> 4. Correlate scan instance to a scan result (1..M)

**Low Priority**
> 1. Add usage scenarios


**Snippet**:

```python
# When we have a standardized CSV, you'll want to implement a validator
# This will ensure that the data you receive is exactly what you expect

from __future__ import print_function

from csvvalidator import CSVValidator


class DNSValidator(CSVValidator):

    whitelist = (
        'Name',
        'Record Type',
        'External IP',
        'Internal IP')

    def __init__(self, field_names=whitelist):
        super(DNSValidator, self).__init__(field_names)

    def validate(self):
        pass

class IPRangeValidator(CSVValidator)

    whitelist = (
        'Domain',
        'IPMan Link',
        'Starting IP',
        'Ending IP',
        'Description',
        'Dept',
        'VLAN',
        'VLAN#')

    def __init__(self, field_names=whitelist):
        super(IPRangeValidator, self).__init__(field_names)

    def validate(self):
        pass

class ValidatorFactory(object):

    @staticmethod
    def factory(validator_type):
        if validator_type == 'dns_dump':
            return DNSValidator()
        if validator_type == 'ip_range':
            return IPRangeValidator()
        print('ERROR: invalid validator: \'{0}\'.'.format(
            validator_type), file=sys.stderr)

```
