CCFLAGS += -Wall -Wextra -Werror -Wno-error=deprecated-declarations

GNMI_PROTOS = sonic_gnoi.proto openconfig_poe.proto sonic_alarm.proto gnmi.proto gnmi_ext.proto system.proto types.proto common.proto openconfig_file_mgmt_private.proto sonic_config_mgmt.proto openconfig_image_management.proto os.proto
GNMI_OBJECTS = $(patsubst %.proto, %.pb.o, $(GNMI_PROTOS)) $(patsubst %.proto, %.grpc.pb.o, $(GNMI_PROTOS))
GNMI_CC_FILES = $(patsubst %.o, %.cc, $(GNMI_OBJECTS))
GNMI_H_FILES = $(patsubst %.o, %.h, $(GNMI_OBJECTS))

all: gnmi_c_connector.full.a

gnmi_protoc_stamp: $(addprefix protos/, $(GNMI_PROTOS))
	/usr/local/bin/protoc-3.21.6.0 --grpc_out ./ --cpp_out ./ -I ./protos --plugin=protoc-gen-grpc="/usr/local/bin/grpc_cpp_plugin" $^
	touch $@

$(GNMI_CC_FILES) $(GNMI_H_FILES): gnmi_protoc_stamp
	test -f $@
	touch $@

$(GNMI_OBJECTS): $(GNMI_CC_FILES) $(GNMI_H_FILES)
	g++ ${CCFLAGS} -I ./ -std=gnu++14 -c -o $@ $(patsubst %.o,%,$@).cc

gnmi_c_connector.o: gnmi_c_connector.cpp gnmi_c_connector.h $(GNMI_H_FILES)
	g++ ${CCFLAGS} -I ./ -std=gnu++14 -c -o $@ $<

gnmi_c_connector.a: gnmi_c_connector.o $(GNMI_OBJECTS)
	ar crs $@ $^

gnmi_c_connector.full.a: gnmi_c_connector.a /usr/local/lib/libabsl_bad_optional_access.a /usr/local/lib/libabsl_bad_variant_access.a /usr/local/lib/libabsl_base.a /usr/local/lib/libabsl_city.a /usr/local/lib/libabsl_civil_time.a /usr/local/lib/libabsl_cord.a /usr/local/lib/libabsl_cord_internal.a /usr/local/lib/libabsl_cordz_functions.a /usr/local/lib/libabsl_cordz_handle.a /usr/local/lib/libabsl_cordz_info.a /usr/local/lib/libabsl_debugging_internal.a /usr/local/lib/libabsl_demangle_internal.a /usr/local/lib/libabsl_exponential_biased.a /usr/local/lib/libabsl_graphcycles_internal.a /usr/local/lib/libabsl_hash.a /usr/local/lib/libabsl_hashtablez_sampler.a /usr/local/lib/libabsl_int128.a /usr/local/lib/libabsl_log_severity.a /usr/local/lib/libabsl_low_level_hash.a /usr/local/lib/libabsl_malloc_internal.a /usr/local/lib/libabsl_random_distributions.a /usr/local/lib/libabsl_random_internal_platform.a /usr/local/lib/libabsl_random_internal_pool_urbg.a /usr/local/lib/libabsl_random_internal_randen.a /usr/local/lib/libabsl_random_internal_randen_hwaes.a /usr/local/lib/libabsl_random_internal_randen_hwaes_impl.a /usr/local/lib/libabsl_random_internal_randen_slow.a /usr/local/lib/libabsl_random_internal_seed_material.a /usr/local/lib/libabsl_random_seed_gen_exception.a /usr/local/lib/libabsl_random_seed_sequences.a /usr/local/lib/libabsl_raw_hash_set.a /usr/local/lib/libabsl_raw_logging_internal.a /usr/local/lib/libabsl_spinlock_wait.a /usr/local/lib/libabsl_stacktrace.a /usr/local/lib/libabsl_status.a /usr/local/lib/libabsl_statusor.a /usr/local/lib/libabsl_str_format_internal.a /usr/local/lib/libabsl_strerror.a /usr/local/lib/libabsl_strings.a /usr/local/lib/libabsl_strings_internal.a /usr/local/lib/libabsl_symbolize.a /usr/local/lib/libabsl_synchronization.a /usr/local/lib/libabsl_throw_delegate.a /usr/local/lib/libabsl_time.a /usr/local/lib/libabsl_time_zone.a /usr/local/lib/libaddress_sorting.a /usr/local/lib/libcares.a /usr/local/lib/libcrypto.a /usr/local/lib/libgpr.a /usr/local/lib/libgrpc++.a /usr/local/lib/libgrpc++_reflection.a /usr/local/lib/libgrpc.a /usr/local/lib/libprotobuf.a /usr/local/lib/libre2.a /usr/local/lib/libssl.a /usr/local/lib/libupb.a /usr/local/lib/libz.a
	ar crsT $@ $^
