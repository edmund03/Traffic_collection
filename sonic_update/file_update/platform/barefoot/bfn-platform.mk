#BFN_PLATFORM = bfnplatform_20220408_sai_1.9.1_deb10.deb
BFN_PLATFORM = bfnplatform_1.0.0_amd64.deb
#BFN_PLATFORM = bfnplatform_20220815_sai_1.10_deb11.deb
#BFN_PLATFORM = bfnplatform_20220704_sai_1.10.2_deb11.deb
#BFN_PLATFORM = bfnplatform_20220127_sai_1.9.1_deb10.deb
#BFN_PLATFORM = bfnplatform_20211216_sai_1.9.1_deb10.deb
#$(BFN_PLATFORM)_URL = "https://github.com/barefootnetworks/sonic-release-pkgs/raw/dev/$(BFN_PLATFORM)"

#SONIC_ONLINE_DEBS += $(BFN_PLATFORM)
#$(BFN_SAI_DEV)_DEPENDS += $(BFN_PLATFORM)
$(BFN_PLATFORM)_PATH = files/pre_build_deb
SONIC_COPY_DEBS += $(BFN_PLATFORM)
$(BFN_SAI_DEV)_DEPENDS += $(BFN_PLATFORM)
