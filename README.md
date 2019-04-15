You can find a modified version of DPDK 17.11 in this repository. It provides support for ath10k based Wi-Fi NICs.
The code released here originates in a research project and is released "as-is". Please feel free to contribute.

This work is created as part of the project "NFV-Framework für sichere Übertragungen in Radio-Mesh-Netzen" funded by RWTÜV Stiftung, Essen, Germany.

You can find further information about the project on the [project page (in German)](https://www.tu-ilmenau.de/telematik/forschung/projekte/nfv-framework-fuer-sichere-uebertragungen-in-radio-mesh-netzen/).

# Build and run device initialization example
```
 $ meson out; cd out
 $ ninja -v
 $ cd app/test-ath10k/
 $ ./dpdk-test-ath10k
```
