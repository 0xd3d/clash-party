# Geo resource provenance

`scripts/update-georesources.sh` downloads `geoip-lite.dat`, `geosite.dat`,
`country-lite.mmdb` and `GeoLite2-ASN.mmdb` from the public latest release of
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat).
The generated `GeoResources.manifest` records each URL, size and SHA-256 digest.
Data files are build inputs and are not checked into this repository.

The upstream repository uses GPL-3.0 (retained in
`ClashParty/Resources/RuleResources/LICENSE-MetaCubeX.txt`). Its aggregation also
includes data from other projects and MaxMind GeoLite2 databases. Preserve the
upstream [source and license notices](https://github.com/MetaCubeX/meta-rules-dat)
and review the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula) before
redistributing database files or a packaged app. The source repository license
does not replace those data-specific terms or Apple's distribution requirements.
