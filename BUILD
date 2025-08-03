
config_setting(
    name = "windows",
    constraint_values = [
        "@platforms//os:windows",
        "@platforms//cpu:x86_64",
    ],
)

config_setting(
    name = "linux",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
)

config_setting(
    name = "macos",
    constraint_values = [
        "@platforms//os:macos",
        "@platforms//cpu:x86_64",
    ],
)

# Library containing platform-specific headers
cc_library(
    name = "os_headers",
    includes = select({
        ":windows": ["vendor/include/windows"],
        ":linux": ["vendor/include/linux"],
        ":macos": ["vendor/include/macos"],
        "//conditions:default": [],  # Default for unsupported platforms
    }),
    visibility = ["//visibility:public"],
    hdrs = glob(
        include = [
            "vendor/include/windows/*.h",
            "vendor/include/linux/*.h",
            "vendor/include/macos/*.h",
        ],
        allow_empty = True,
    ),
)

# Client binary
cc_binary(
    name = "client",
    linkopts = ["-lpcap"],
    deps = [
        ":os_headers",
        "//protos:cpp_grpc_threathunter_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:initialize",
        "@grpc//:grpc++",
    ],
    srcs = select({
        ":linux": ["client.cc", "vendor/include/linux/linux_monitor.cc"],
        ":windows": ["client.cc", "vendor/include/windows/monitor.cc"],
        ":macos": ["client.cc", "vendor/include/macos/monitor.cc"],  # macOS-specific source files
        "//conditions:default": ["client.cc"],
    }),
    includes = select({
        ":linux": ["protos/cpp_grpc_threathunter_proto_pb/protos", "vendor/include/linux"],
        ":windows": ["protos/cpp_grpc_threathunter_proto_pb/protos", "vendor/include/windows"],
        ":macos": ["protos/cpp_grpc_threathunter_proto_pb/protos", "vendor/include/macos"],  # macOS-specific includes
        "//conditions:default": ["protos/cpp_grpc_threathunter_proto_pb/protos"],
    }),
)

# Server binary
cc_binary(
    name = "server",
    srcs = ["server.cc"],
    includes = [
        "protos/cpp_grpc_threathunter_proto_pb/protos",  # Relative path for protos
    ],
    deps = [
        ":os_headers",
        "//protos:cpp_grpc_threathunter_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:initialize",
        "@grpc//:grpc++",
    ],
)

