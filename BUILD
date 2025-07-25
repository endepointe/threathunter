
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

cc_library(
    name = "os_headers",
    includes = select({
        ":windows": ["vendor/include/windows"],
        ":linux": ["vendor/include/linux"],
        ":macos": ["vendor/include/macos"],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
    srcs = glob(
        include = [
            "vendor/include/windows/*.cc",
            "vendor/include/linux/*.cc",
            "vendor/include/macos/*.cc"
        ],
        allow_empty = True
    ),
    hdrs = glob(
        include = [
            "vendor/include/windows/*.h",
            "vendor/include/linux/*.h",
            "vendor/include/macos/*.h"
        ],
        allow_empty = True
    )
)

cc_binary(
    name = "client",
    srcs = ["client.cc"],
    includes = [
        "/usr/include/math.h",
        "/usr/include/pcap/", # build header file into binary instead of making it system dependent.
        "bazel-bin/protos/cpp_grpc_threathunter_proto_pb/protos/"
    ],
    linkopts = ["-lpcap"],
    deps = [
        ":os_headers",
        "//protos:cpp_grpc_threathunter_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:initialize",
        "@grpc//:grpc++",
        "@grpc//:grpc",
    ],
)

cc_binary(
    name = "server",
    srcs = ["server.cc"],
    includes = [
        "/usr/include/math.h",
        "bazel-bin/protos/cpp_grpc_threathunter_proto_pb/protos/"
    ],
    deps = [
        ":os_headers",
        "//protos:cpp_grpc_threathunter_proto",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:initialize",
        "@grpc//:grpc++",
        "@grpc//:grpc",
    ],
)

