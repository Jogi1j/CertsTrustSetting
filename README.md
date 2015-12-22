# CertsTrustSetting
Firefox Addon

Certification trust settings.

In your profile direcory create directory "CertsTrustSetting".

Insert 3 json file with certs =
  1. certs.json - all certs,
  2. certsSelection.json - only your selection of trust certs and
  3. certsImportant.json with only important certs).

Then you can delete trust of all certs form certs.json and inport only selected or important list certs from this addon. If cert is not in json file, then will not edit cert's trust.
