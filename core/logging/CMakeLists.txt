add_library(logging logging.cc log_generator.cc debug_stream.cc file_stream.cc fog_stream.cc syslog_stream.cc cef_stream.cc k8s_svc_stream.cc)

add_subdirectory(logging_ut)
