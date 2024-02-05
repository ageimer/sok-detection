# Module for CT Analysis

#### By [Mathéo VERGNOLLE](mailto:matheo.vergnolle@polytechnique.edu)
#### Based on thesis work by [Lesly-Ann DANIEL](https://leslyann-daniel.fr/)

This code as been made so that it has a minimal diff with the [SSE module](../sse/). The main differences are :
- the old execution engine ("formula") has been deleted, only the new one ("terms") is supported
- [parser](./script_parser.mly) has been changed to allow declaration of secrets
- code is added for CT analysis along the exploration, mostly in [checkct.ml](./checkct.ml) and [senv.ml](./term/senv.ml)

An high-level description of the CT analysis done here can be found in [my report](https://git.frama-c.com/vergnolle/rapportsoutenance).

The benchmark used are on the bintest repository, on a [dedicated branch](https://git.frama-c.com/binary/bintests/-/tree/matheo/checkct-tests).

