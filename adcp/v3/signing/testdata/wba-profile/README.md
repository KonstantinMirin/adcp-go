# Experimental Web Bot Auth vectors

Copied without modification from adcontextprotocol/adcp PR #7894, commit
`656bd080f01cc2fca4a1e623af44e96cfd827ba5`,
`static/compliance/source/test-vectors/wba-profile/` (`keys.json`,
`positive/`, `negative/`), the same commit the Python SDK vendors.

These are draft transport vectors for the experimental AdCP 3.3 Web Bot Auth
profile, not released compliance inputs. Replace them from the released
`test-vectors/wba-profile/` set when AdCP 3.3 ships. The `governance/`
vectors are not vendored: governance JWS stays on the RFC 9421 chain in 3.3.
The private seeds in `keys.json` are public test inputs only.
