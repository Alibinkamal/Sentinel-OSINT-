"""
Phone number intelligence — fully offline, no API key.
Uses google-libphonenumber (the `phonenumbers` package): validity, region,
carrier, line type and timezones — all from the bundled metadata.
"""
try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone
    _HAS = True
except Exception:
    _HAS = False

_LINE_TYPES = {
    0: "Fixed line", 1: "Mobile", 2: "Fixed line or mobile", 3: "Toll free",
    4: "Premium rate", 5: "Shared cost", 6: "VoIP", 7: "Personal number",
    8: "Pager", 9: "UAN", 10: "Unknown", 27: "Emergency", 28: "Voicemail",
}


def analyze(number: str, default_region: str = None) -> dict:
    number = (number or "").strip()
    out = {"selector": number, "type": "phone", "valid": False}
    if not _HAS:
        out["error"] = "phonenumbers not installed"
        return out
    try:
        parsed = phonenumbers.parse(number, default_region)
    except Exception as e:
        out["error"] = f"Could not parse ({type(e).__name__}). Include the country code, e.g. +9647701234567."
        return out

    valid = phonenumbers.is_valid_number(parsed)
    out.update({
        "valid": valid,
        "possible": phonenumbers.is_possible_number(parsed),
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
        "country_code": parsed.country_code,
        "region": geocoder.region_code_for_number(parsed) or "",
        "location": geocoder.description_for_number(parsed, "en") or "",
        "carrier": carrier.name_for_number(parsed, "en") or "",
        "line_type": _LINE_TYPES.get(phonenumbers.number_type(parsed), "Unknown"),
        "timezones": list(timezone.time_zones_for_number(parsed)),
    })
    return out
