from modules.module import Module
from lib.utils import translate_flags, convert_wi8_timestamp_to_timedelta

import asyncio

pwdproperties_flags = {
        'PASSWORD_COMPLEX':0x01,
        'PASSWORD_NO_ANON_CHANGE': 0x02,
        'PASSWORD_NO_CLEAR_CHANGE': 0x04,
        'LOCKOUT_ADMINS': 0x08,
        'PASSWORD_STORE_CLEARTEXT': 0x10,
        'REFUSE_PASSWORD_CHANGE': 0x20
        }

useraccountcontrol_flags = {"SCRIPT": 1,
        "ACCOUNTDISABLE": 2,
        "HOMEDIR_REQUIRED": 8,
        "LOCKOUT": 16,
        "PASSWD_NOTREQD": 32,
        "PASSWD_CANT_CHANGE": 64,
        "ENCRYPTED_TEXT_PWD_ALLOWED": 128,
        "TEMP_DUPLICATE_ACCOUNT": 256,
        "NORMAL_ACCOUNT": 512,
        "INTERDOMAIN_TRUST_ACCOUNT": 2048,
        "WORKSTATION_TRUST_ACCOUNT": 4096,
        "SERVER_TRUST_ACCOUNT": 8192,
        "DONT_EXPIRE_PASSWORD": 65536,
        "MNS_LOGON_ACCOUNT": 131072,
        "SMARTCARD_REQUIRED": 262144,
        "TRUSTED_FOR_DELEGATION": 524288,
        "NOT_DELEGATED": 1048576,
        "USE_DES_KEY_ONLY": 2097152,
        "DONT_REQ_PREAUTH": 4194304,
        "PASSWORD_EXPIRED": 8388608,
        "TRUSTED_TO_AUTH_FOR_DELEGATION": 16777216,
        "PARTIAL_SECRETS_ACCOUNT": 67108864}



class PassPol:
    def __init__(self, ldap_result, passpol_type="PSO"):
        pol_attrs = ldap_result['attributes']
        self.type = passpol_type
        if passpol_type == "PSO":
            self.name = pol_attrs['name']
            self.description = pol_attrs['description'] \
                    if "description" in pol_attrs.keys() else None
            self.dn = pol_attrs['distinguishedName']
            self.maximumPasswordAge = convert_wi8_timestamp_to_timedelta(
                    pol_attrs['msDS-MaximumPasswordAge'][0].decode()).days
            self.minimumPasswordAge = convert_wi8_timestamp_to_timedelta(
                    pol_attrs['msDS-MinimumPasswordAge'][0].decode()).days
            self.minimumPasswordLength = \
                    int(pol_attrs['msDS-MinimumPasswordLength'][0].decode())
            self.passwordHistoryLength = \
                    int(pol_attrs['msDS-PasswordHistoryLength'][0].decode())
            self.passwordComplexityEnabled = \
                    pol_attrs['msDS-PasswordComplexityEnabled'][0].decode()== 'TRUE'
            self.passwordReversibleEncryptionEnabled = \
                    pol_attrs['msDS-PasswordReversibleEncryptionEnabled'][0].decode() == 'TRUE'
            self.lockoutObservationWindow = convert_wi8_timestamp_to_timedelta(
                    pol_attrs['msDS-LockoutObservationWindow'][0].decode())\
                            .total_seconds()/60
            self.lockoutDuration = convert_wi8_timestamp_to_timedelta(
                    pol_attrs['msDS-LockoutDuration'][0].decode())\
                            .total_seconds()/60
            self.lockoutThreshold = pol_attrs['msDS-LockoutThreshold'][0].decode()
            self.PSOAppliesTo = [group.decode() for group in pol_attrs['msDS-PSOAppliesTo']] \
                    if 'msDS-PSOAppliesTo' in pol_attrs.keys() else []
            self.passwordSettingsPrecedence = \
                    int(pol_attrs['msDS-PasswordSettingsPrecedence'][0].decode())
        elif passpol_type == "Default":
            self.name = "Default Password Policy"
            self.description = None
            self.dn = ldap_result["objectName"]
            self.lockoutDuration = convert_wi8_timestamp_to_timedelta(
                    pol_attrs['lockoutDuration']).total_seconds()/60
            self.lockoutObservationWindow = convert_wi8_timestamp_to_timedelta(
                    pol_attrs['lockOutObservationWindow']).total_seconds()/60
            self.lockoutThreshold = int(pol_attrs['lockoutThreshold'])
            self.maximumPasswordAge = pol_attrs['maxPwdAge'].days
            self.minimumPasswordAge = pol_attrs['minPwdAge'].days
            self.minimumPasswordLength = int(pol_attrs['minPwdLength'])
            self.passwordHistoryLength = int(pol_attrs['pwdHistoryLength'])
            flags = translate_flags(pol_attrs['pwdProperties'], pwdproperties_flags)
            self.passwordComplexityEnabled = True if 'PASSWORD_COMPLEX' \
                    in flags else False
            self.passwordReversibleEncryptionEnabled = True \
                    if 'PASSWORD_STORE_CLEARTEXT' in flags else False
            self.PSOAppliesTo = []

    def __repr__(self):
        to_return = f"""{self.name} ({self.type})
    DN: {self.dn}
    Description: {self.description}
    minimumPasswordLength: {self.minimumPasswordLength}
    maximumPasswordAge: {self.maximumPasswordAge} days
    minimumPasswordAge: {self.minimumPasswordAge} days
    lockoutThreshold: {self.lockoutThreshold}
    lockoutDuration: {self.lockoutDuration} minutes
    lockoutObservationWindow: {self.lockoutObservationWindow} minutes
    passwordComplexityEnabled: {self.passwordComplexityEnabled}
    passwordReversibleEncryptionEnabled: {self.passwordReversibleEncryptionEnabled}
    """
        if self.type == "PSO":
            to_return += "PSOAppliesTo:\n\t"
            to_return += '\n\t'.join(self.PSOAppliesTo)
        return to_return

class Policy(Module):
    async def _work(self):
        passpols = []
        # Define default password policy attributes and get it from LDAP
        attributes = [
                'lockoutDuration',
                'lockOutObservationWindow',
                'lockoutThreshold',
                'maxPwdAge',
                'minPwdAge',
                'minPwdLength',
                'pwdProperties',
                'pwdHistoryLength',
                'pwdProperties',
                ]
        # Iterator[(dict, Exception)]
        default_passpol = self.ldap_client.pagedsearch('(objectClass=domain)',
                attributes)
        async for passpol, exc in default_passpol:
            passpol = PassPol(passpol, passpol_type="Default")
            passpols.append(passpol)
        # Define PSO attibutes and get it from LDAP
        attributes = [
                'description',
                'name',
                'distinguishedName',
                'msDS-MaximumPasswordAge',
                'msDS-MinimumPasswordAge',
                'msDS-MinimumPasswordLength',
                'msDS-PasswordHistoryLength',
                'msDS-PasswordComplexityEnabled',
                'msDS-PasswordReversibleEncryptionEnabled',
                'msDS-LockoutObservationWindow',
                'msDS-LockoutDuration',
                'msDS-LockoutThreshold',
                'msDS-PasswordSettingsPrecedence',
                'msDS-PSOAppliesTo',
                'whenCreated',
                'whenChanged'
                ]
        # Iterator[(dict, Exception)]
        search = self.ldap_client.pagedsearch('(objectClass=msDS-PasswordSettings)', 
                attributes)
        async for passpol, exc in search:
            if exc is not None:
                raise exc
            passpol = PassPol(passpol)
            passpols.append(passpol)
        self.data = passpols


    async def _result(self):
        to_return = f"{'Policy name':<40}|{'MinPwdLen':^15}|{'MaxPwdAge (days)':^15}|{'LockTreshold':^15}|{'LockDuration (mins)':^15}|{'Complexity':^15}\n"
        for passpol in self.data:
            to_return += f"{passpol.name:<40} {passpol.minimumPasswordLength:^15} {passpol.maximumPasswordAge:^15} {passpol.lockoutThreshold:^15} {passpol.lockoutDuration:^15} {passpol.passwordComplexityEnabled:^15}\n"
        return to_return

