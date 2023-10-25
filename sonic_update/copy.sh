#fix bug
cp file_update/src/sonic-build-hooks/Makefile ../sonic-buildimage/src/sonic-build-hooks/
cp file_update/build_debian.sh ../sonic-buildimage/
cp file_update/rules/snmpd.mk ../sonic-buildimage/rules/snmpd.mk
cp file_update/src/snmpd/Makefile ../sonic-buildimage/src/snmpd/
cp file_update/rules/debootstrap.mk ../sonic-buildimage/rules/
cp file_update/sonic-buildimage/src/isc-dhcp/Makefile ../sonic-buildimage/src/isc-dhcp/
cp file_update/rules/isc-dhcp.mk ../sonic-buildimage//rules/

#update
cp -r file_update/src/sonic-p4rt/sonic-pins/p4rt_app ../sonic-buildimage/src/sonic-p4rt/sonic-pins/
cp -r file_update/src/sonic-p4rt/sonic-pins/p4_pdpi ../sonic-buildimage/src/sonic-p4rt/sonic-pins/
cp -r file_update/src/sonic-p4rt/sonic-pins/sai_p4 ../sonic-buildimage/src/sonic-p4rt/sonic-pins/
cp -r file_update/src/sonic-swss/orchagent/p4orch ../sonic-buildimage/src/sonic-swss/orchagent/
cp file_update/src/sonic-swss/orchagent/Makefile.am ../sonic-buildimage/src/sonic-swss/orchagent/
cp file_update/src/sonic-swss/orchagent/p4orch/tests/Makefile.am ../sonic-buildimage/src/sonic-swss/orchagent/p4orch/tests/
cp file_update/src/sonic-swss/tests/mock_tests/Makefile.am ../sonic-buildimage/src/sonic-swss/tests/mock_tests/
cp file_update/src/sonic-p4rt/Makefile ../sonic-buildimage/src/sonic-p4rt/

#update sai sdk
cp file_update/platform/barefoot/docker-syncd-bfn-rpc.mk ../sonic-buildimage/platform/barefoot/
cp file_update/platform/barefoot/docker-syncd-bfn-rpc/Dockerfile.j2 ../sonic-buildimage/platform/barefoot/docker-syncd-bfn-rpc
cp file_update/platform/barefoot/docker-syncd-bfn.mk ../sonic-buildimage/platform/barefoot/
cp file_update/platform/barefoot/docker-syncd-bfn/Dockerfile.j2 ../sonic-buildimage/platform/barefoot/docker-syncd-bfn/
cp file_update/platform/barefoot/bfn-platform.mk ../sonic-buildimage/platform/barefoot/
cp file_update/platform/barefoot/bfn-sai.mk ../sonic-buildimage/platform/barefoot/
cp -r file_update/files/pre_build_deb/ ../sonic-buildimage/files/
