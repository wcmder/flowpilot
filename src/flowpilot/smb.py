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
    "0x00000103": "STATUS_PENDING",
    "0x0000010b": "STATUS_NOTIFY_CLEANUP",
    "0x0000010c": "STATUS_NOTIFY_ENUM_DIR",
    "0x4000000f": "STATUS_BUFFER_OVERFLOW",
    "0x80000005": "STATUS_BUFFER_OVERFLOW",
    "0x80000006": "STATUS_NO_MORE_FILES",
    "0x8000000d": "STATUS_PARTIAL_COPY",
    "0xc0000001": "STATUS_UNSUCCESSFUL",
    "0xc0000002": "STATUS_NOT_IMPLEMENTED",
    "0xc0000008": "STATUS_INVALID_HANDLE",
    "0xc000000d": "STATUS_INVALID_PARAMETER",
    "0xc0000010": "STATUS_INVALID_DEVICE_REQUEST",
    "0xc0000011": "STATUS_END_OF_FILE",
    "0xc0000022": "STATUS_ACCESS_DENIED",
    "0xc0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
    "0xc0000035": "STATUS_OBJECT_NAME_COLLISION",
    "0xc000003a": "STATUS_OBJECT_PATH_NOT_FOUND",
    "0xc0000043": "STATUS_SHARING_VIOLATION",
    "0xc0000054": "STATUS_FILE_LOCK_CONFLICT",
    "0xc000006d": "STATUS_LOGON_FAILURE",
    "0xc00000bb": "STATUS_NOT_SUPPORTED",
    "0xc00000cc": "STATUS_BAD_NETWORK_NAME",
    "0xc00000d0": "STATUS_REQUEST_NOT_ACCEPTED",
    "0xc00000e5": "STATUS_INTERNAL_ERROR",
    "0xc0000120": "STATUS_CANCELLED",
    "0xc0000205": "STATUS_INSUFF_SERVER_RESOURCES",
    "0xc0000225": "STATUS_NOT_FOUND",
    "0xc0000234": "STATUS_ACCOUNT_LOCKED_OUT",
    "0xc0000257": "STATUS_PATH_NOT_COVERED",
    "0xc000035c": "STATUS_NETWORK_SESSION_EXPIRED",
}


def smb_command_label(command: str) -> str:
    return _lookup_smb_name(command, SMB_COMMAND_NAMES) or command


def smb_display_value(value: str, names: dict[str, str]) -> str:
    label = _lookup_smb_name(value, names)
    if label:
        return f"{label}({value})"
    if names is SMB_STATUS_NAMES and _is_hex_value(value):
        return f"NTSTATUS_UNKNOWN({value})"
    return value


def _lookup_smb_name(value: str, names: dict[str, str]) -> str | None:
    normalized = value.lower()
    return names.get(value) or names.get(normalized)


def _is_hex_value(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return value.lower().startswith("0x")
