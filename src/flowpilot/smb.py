SMB_COMMAND_NAMES = {
    "0": "SMBmkdir",
    "0x00": "SMBmkdir",
    "1": "SMBrmdir",
    "0x01": "SMBrmdir",
    "2": "SMBopen",
    "0x02": "SMBopen",
    "3": "SMBcreate",
    "0x03": "SMBcreate",
    "4": "SMBclose",
    "0x04": "SMBclose",
    "5": "SMBflush",
    "0x05": "SMBflush",
    "6": "SMBunlink",
    "0x06": "SMBunlink",
    "7": "SMBmv",
    "0x07": "SMBmv",
    "8": "SMBgetatr",
    "0x08": "SMBgetatr",
    "9": "SMBsetatr",
    "0x09": "SMBsetatr",
    "10": "SMBread",
    "0x0a": "SMBread",
    "11": "SMBwrite",
    "0x0b": "SMBwrite",
    "12": "SMBlock",
    "0x0c": "SMBlock",
    "13": "SMBunlock",
    "0x0d": "SMBunlock",
    "14": "SMBctemp",
    "0x0e": "SMBctemp",
    "15": "SMBmknew",
    "0x0f": "SMBmknew",
    "16": "SMBchkpth",
    "0x10": "SMBchkpth",
    "17": "SMBexit",
    "0x11": "SMBexit",
    "18": "SMBlseek",
    "0x12": "SMBlseek",
    "19": "SMBlockread",
    "0x13": "SMBlockread",
    "20": "SMBwriteunlock",
    "0x14": "SMBwriteunlock",
    "37": "SMBtrans",
    "0x25": "SMBtrans",
    "45": "SMBopenX",
    "0x2d": "SMBopenX",
    "46": "SMBreadX",
    "0x2e": "SMBreadX",
    "47": "SMBwriteX",
    "0x2f": "SMBwriteX",
    "50": "SMBtrans2",
    "0x32": "SMBtrans2",
    "114": "SMBnegprot",
    "0x72": "SMBnegprot",
    "115": "SMBsesssetupX",
    "0x73": "SMBsesssetupX",
    "117": "SMBtconX",
    "0x75": "SMBtconX",
    "162": "SMBntcreateX",
    "0xa2": "SMBntcreateX",
}

SMB_STATUS_NAMES = {
    "0": "STATUS_SUCCESS",
    "0x00000000": "STATUS_SUCCESS",
}


def smb_command_label(command: str) -> str:
    return _lookup_smb_name(command, SMB_COMMAND_NAMES) or command


def smb_display_value(value: str, names: dict[str, str]) -> str:
    label = _lookup_smb_name(value, names)
    if label:
        return f"{label}({value})"
    return value


def _lookup_smb_name(value: str, names: dict[str, str]) -> str | None:
    normalized = value.lower()
    return names.get(value) or names.get(normalized)
