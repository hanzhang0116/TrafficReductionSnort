
##Snort Speedup Preprocessor

Snort heavily relies on DPI techniques, such as searching for suspicious strings in packet payload. However, certain content, such as video, audio, encrypted or compressed data, cannot be understood by the IDS and results in a waste of computation resources.

To address the above issue, we design and implement a Snort preprocessor to label traffic as clear or opaque. Here we name the data can be understood by DPI as clear data, and name the others as opaque (e.g., encrypted data). Then, we only deliver the clear traffic to the IDS and discard the rest. By doing this, the preprocessor reduces the amount of traffic delivered to IDS by more than 50%, while maintaining more than 99.9% of the original alerts.

As most of the files are the same as Snort distribution, only the modified files were uploaded here. The Snort distribution can downloaded [here] (https://www.snort.org/downloads).

More details can be found in my published paper [here] (http://www.cs.colostate.edu/~hanzhang/papers/EarlyDetection.pdf)

>Included Files:
- src/spp_entropy.c:
	* The high entropy preprocessor source file
- src/spp_entropy.h:
	* The high entropy preprocessor header file
- src/preprocessors/EntropyThreshold_PY_64K:
	* The entropy threshold file
- src/generators.h:
	*  Added:
	* #define	GENERATOR_SPP_ENTROPY	104
	* #define	HE_TRAFFIC_DETECT	1
- src/plugbase.c:
	* Added:
	* #include "preprocessors/spp_entropy.h"
	* SetupEntropy();
- src/preprocids.h:
	* Added:
	* #define	PP_ENTROPY	32
- src/preprocessors/Makefile*
	* Added spp_entropy entries
- etc/gen-msg.map: 
	* Added "146 || 1 || spp_entropy: High Entropy Traffic"
- etc/snort-TrafficReduction.conf:
	* Enable the preprocessor: "preprocessor entropy: he_percent 90, seq_he_pkts 2, first_pkts 15"
	* Include the rule: "include $PREPROC_RULE_PATH/highentropy.rules"
- rules/preproc_rules/highentropy.rules:
	* The high entropy preprocessor rule
