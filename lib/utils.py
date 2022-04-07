from datetime import timedelta


def import_module(name, ldap_client):
    module_class = getattr(
        __import__(
            f'modules.{name}',
            fromlist=[name]
        ),
        name.capitalize(),
    )
    return module_class(name, ldap_client)
    

def translate_flags(value, flags):
    result = []
    for flag, bit in flags.items():
        if (value & bit) != 0:
            result.append(flag)
    return result


def convert_wi8_timestamp_to_timedelta(timestamp):
    # https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/convert-datetime-attributes-to-standard-format
    # https://docs.microsoft.com/en-us/windows/win32/adschema/a-lockouttime
    timestamp = int(timestamp)
    if timestamp < 0:
        timestamp = -timestamp
    return timedelta(seconds=timestamp/10000000)
