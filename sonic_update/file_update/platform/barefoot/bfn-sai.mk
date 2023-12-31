#BFN_SAI = bfnsdk_20220408_sai_1.9.1_deb10.deb
#$(BFN_SAI)_URL = "https://github.com/barefootnetworks/sonic-release-pkgs/raw/dev/$(BFN_SAI)"
#BFN_SAI = bfnsdk_20220815_sai_1.10_deb11.deb
#BFN_SAI = bfnsdk_20220704_sai_1.10.2_deb11.deb
#BFN_SAI = bfnsdk_20220127_sai_1.9.1_deb10.deb
#BFN_SAI = bfnsdk_20211216_sai_1.9.1_deb10.deb
#$(BFN_SAI)_URL = "https://github.com/barefootnetworks/sonic-release-pkgs/raw/dev/$(BFN_SAI)"
BFN_SAI = bfnsdk_1.0.0_amd64.deb
$(BFN_SAI)_PATH = files/pre_build_deb

$(BFN_SAI)_DEPENDS += $(LIBNL_GENL3_DEV)
$(eval $(call add_conflict_package,$(BFN_SAI),$(LIBSAIVS_DEV)))
$(BFN_SAI)_RDEPENDS += $(LIBNL_GENL3)

#SONIC_ONLINE_DEBS += $(BFN_SAI)
SONIC_COPY_DEBS += $(BFN_SAI)
$(BFN_SAI_DEV)_DEPENDS += $(BFN_SAI)
